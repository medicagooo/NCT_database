import type {
  AdminSnapshot,
  AnalyticsOverview,
  DataSourceType,
  DownstreamClient,
  IngestRecordInput,
  IngestResult,
  JsonObject,
  JsonValue,
  PublicDatasetItem,
  PublicDatasetResponse,
  RawRecord,
  SecureRecord,
  SecureTransferPayload,
  SchoolMediaOverview,
  SchoolMediaRecord,
  SchoolMediaStats,
  SchoolMediaStatus,
  SchoolMediaTag,
  SubDatabackExportFile,
  SubFormRecordResult,
  SubFormRecordsRequest,
  SubMediaRecordResult,
  SubMediaRecordsRequest,
  SubPushPayload,
  SubPushRecord,
  SubReportPayload,
  SyncPayload,
  SyncRequest,
} from '../../shared/types';
import {
  decryptObject,
  encryptObject,
  sha256,
} from './crypto';
import {
  ensureDynamicColumns,
  extractDynamicColumns,
  serializeDynamicColumnValue,
} from './dynamic-schema';
import {
  parseJsonObject,
  parseStringArray,
  stableStringify,
  toJsonObject,
} from './json';
import {
  computeRecordContentFingerprint,
  deriveRecordContentVersion,
} from './record-version';
import {
  deriveServiceAuthToken,
  verifyServiceAuthToken,
} from './service-auth';

type RawRecordRow = Record<string, unknown> & {
  data_source_type?: string | null;
  id: string;
  record_key: string;
  source: string;
  version: number;
  payload_json: string;
  payload_hash: string;
  received_at: string;
  processed_at: string | null;
  created_at: string;
  updated_at: string;
};

type SecureRecordRow = Record<string, unknown> & {
  data_source_type?: string | null;
  id: string;
  raw_record_id: string;
  record_key: string;
  version: number;
  key_version: number;
  public_json: string;
  encrypted_json: string;
  encrypt_fields_json: string;
  fingerprint: string;
  synced_at: string | null;
  created_at: string;
  updated_at: string;
};

type DownstreamClientRow = {
  id: number;
  entry_kind: string | null;
  client_name: string | null;
  callback_url: string;
  client_version: number;
  last_sync_version: number;
  last_seen_at: string;
  last_push_at: string | null;
  last_status: string;
  last_response_code: number | null;
  last_error: string | null;
  service_url: string | null;
  databack_version: number | null;
  report_count: number | null;
  reported_at: string | null;
  payload_json: string | null;
  last_pull_version: number | null;
  last_pull_at: string | null;
  last_pull_status: string | null;
  last_pull_response_code: number | null;
  last_pull_error: string | null;
  auth_failure_count: number | null;
  blacklisted_at: string | null;
  auth_token_hash: string | null;
  auth_issued_at: string | null;
  auth_last_success_at: string | null;
  auth_last_failure_at: string | null;
};

type MediaTagRow = {
  id: string;
  slug: string;
  label: string;
  normalized_label: string;
  is_system: number;
  created_at: string;
  updated_at: string;
};

type SchoolMediaRow = {
  id: string;
  source_service_url: string;
  source_media_id: string;
  object_key: string;
  local_object_key: string | null;
  public_url: string;
  media_type: 'image' | 'video';
  content_type: string;
  byte_size: number;
  file_name: string;
  school_name: string;
  school_name_norm: string;
  school_address: string;
  province: string;
  city: string;
  county: string;
  is_r18: number;
  status: SchoolMediaStatus;
  review_note: string | null;
  uploaded_at: string | null;
  object_synced_at: string | null;
  reviewed_at: string | null;
  source_updated_at: string;
  created_at: string;
  updated_at: string;
};

type ColumnAssignment = {
  column: string;
  value: string | null;
};

const RECOGNIZED_SUB_SERVICES = new Set([
  'NCT API SQL Sub',
  'nct-api-sql-sub',
]);
export const NCT_SUB_SERVICE_WATERMARK = 'nct-api-sql-sub:v1';
const SUB_PUSH_PATH = '/api/push/secure-records';
const SUB_EXPORT_PATH = '/api/export/nct_databack';
const CURRENT_ENCRYPTION_KEY_VERSION = 1;
const SUB_FORM_SOURCE_PREFIX = 'sub-form:';
const SUB_RECOVERY_SOURCE_PREFIX = 'sub-recovery:';
const DATA_SOURCE_TYPES = new Set<DataSourceType>([
  'questionnaire',
  'batch_query',
]);
const R18_TAG_ID = 'tag:r18';
const R18_TAG_SLUG = 'r18';

function nowIso(): string {
  return new Date().toISOString();
}

function readStringField(
  payload: JsonObject,
  fieldName: string,
): string {
  const value = payload[fieldName];

  if (typeof value === 'string') {
    return value;
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }

  return '';
}

function readNumberField(
  payload: JsonObject,
  fieldName: string,
): number | null {
  const value = payload[fieldName];

  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string') {
    const parsed = Number(value.trim());
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }

  return null;
}

function mapPublicDatasetItem(
  record: RawRecord,
): PublicDatasetItem {
  const payload = record.payload;

  return {
    name: readStringField(payload, 'name'),
    addr: readStringField(payload, 'addr'),
    province: readStringField(payload, 'province'),
    prov: readStringField(payload, 'prov'),
    else: readStringField(payload, 'else'),
    lat: readNumberField(payload, 'lat'),
    lng: readNumberField(payload, 'lng'),
    experience: readStringField(payload, 'experience'),
    HMaster: readStringField(payload, 'HMaster'),
    scandal: readStringField(payload, 'scandal'),
    contact: readStringField(payload, 'contact'),
    inputType: readStringField(payload, 'inputType'),
  };
}

function quoteIdentifier(
  identifier: string,
): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

function buildInsertStatement(
  tableName: string,
  columns: string[],
): string {
  return `
    INSERT INTO ${quoteIdentifier(tableName)} (
      ${columns.map((column) => quoteIdentifier(column)).join(', ')}
    )
    VALUES (${columns.map(() => '?').join(', ')})
  `;
}

function buildUpdateStatement(
  tableName: string,
  columns: string[],
  whereColumn: string,
): string {
  return `
    UPDATE ${quoteIdentifier(tableName)}
    SET ${columns
      .map((column) => `${quoteIdentifier(column)} = ?`)
      .join(', ')}
    WHERE ${quoteIdentifier(whereColumn)} = ?
  `;
}

function getDefaultEncryptFields(env: Env): string[] {
  return (env.DEFAULT_ENCRYPT_FIELDS ?? '')
    .split(',')
    .map((field) => field.trim())
    .filter(Boolean);
}

function readRecordKey(
  input: IngestRecordInput,
): string {
  const payload = input.payload as Record<string, unknown>;

  const candidates = [
    input.recordKey,
    typeof payload.recordKey === 'string' ? payload.recordKey : undefined,
    typeof payload.id === 'string' ? payload.id : undefined,
    typeof payload.externalId === 'string' ? payload.externalId : undefined,
    typeof payload.code === 'string' ? payload.code : undefined,
  ];

  const resolved = candidates.find(
    (candidate) => typeof candidate === 'string' && candidate.trim().length > 0,
  );

  return resolved ?? crypto.randomUUID();
}

function partitionPayload(
  payload: JsonObject,
  encryptFields: string[],
): {
  publicData: JsonObject;
  secretData: JsonObject;
} {
  const encryptedFieldSet = new Set(encryptFields);
  const publicData: JsonObject = {};
  const secretData: JsonObject = {};

  Object.entries(payload).forEach(([key, value]) => {
    if (encryptedFieldSet.has(key)) {
      secretData[key] = value;
      return;
    }

    publicData[key] = value;
  });

  return {
    publicData,
    secretData,
  };
}

async function getCurrentVersion(
  db: D1Database,
): Promise<number> {
  const result = await db
    .prepare(
      'SELECT COALESCE(MAX(version), 0) AS version FROM secure_records',
    )
    .first<{ version: number | null }>();

  return Number(result?.version ?? 0);
}

function collectFieldNames(
  ...groups: Iterable<string>[]
): string[] {
  const fieldNames = new Set<string>();

  groups.forEach((group) => {
    for (const fieldName of group) {
      const trimmedFieldName = fieldName.trim();
      if (trimmedFieldName) {
        fieldNames.add(trimmedFieldName);
      }
    }
  });

  return Array.from(fieldNames).sort((left, right) =>
    left.localeCompare(right),
  );
}

function isJsonObject(value: JsonValue | undefined): value is JsonObject {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function readSubmittedFields(values: Record<string, JsonValue>): JsonObject {
  return isJsonObject(values.submittedFields) ? values.submittedFields : {};
}

function collectPayloadFieldNames(...payloads: JsonObject[]): string[] {
  return collectFieldNames(
    ...payloads.flatMap((payload) => [
      Object.keys(payload),
      Object.keys(readSubmittedFields(payload)),
    ]),
  );
}

function hasOwn(
  value: object,
  key: string,
): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function readDynamicFieldValue(
  values: Record<string, JsonValue>,
  fieldName: string,
): JsonValue | undefined {
  if (hasOwn(values, fieldName)) {
    return values[fieldName];
  }

  const submittedFields = readSubmittedFields(values);
  return hasOwn(submittedFields, fieldName)
    ? submittedFields[fieldName]
    : undefined;
}

function normalizeDataSourceType(
  value: unknown,
  fallback: DataSourceType,
): DataSourceType {
  return typeof value === 'string' && DATA_SOURCE_TYPES.has(value as DataSourceType)
    ? value as DataSourceType
    : fallback;
}

function inferDataSourceType(
  payload: JsonObject,
  source = '',
): DataSourceType {
  const payloadSource = typeof payload.source === 'string' ? payload.source : '';
  const recordKind = typeof payload.recordKind === 'string' ? payload.recordKind : '';
  const publicData = isJsonObject(payload.publicData) ? payload.publicData : {};

  if (
    source.startsWith(SUB_FORM_SOURCE_PREFIX)
    || source.startsWith('admin-questionnaire-import')
    || payloadSource === 'No-Torsion'
    || recordKind.startsWith('no_torsion_')
    || isJsonObject(payload.submittedFields)
    || publicData.source === 'No-Torsion'
    || (
      typeof publicData.recordKind === 'string'
      && publicData.recordKind.startsWith('no_torsion_')
    )
  ) {
    return 'questionnaire';
  }

  return 'batch_query';
}

function buildDynamicAssignments(
  mappings: Map<string, string>,
  fieldNames: Iterable<string>,
  values: Record<string, JsonValue>,
): ColumnAssignment[] {
  // When a field exists in the evolving schema but not in this payload, write NULL so old values do not linger on update.
  const assignmentsByColumn = new Map<string, ColumnAssignment>();

  for (const fieldName of collectFieldNames(fieldNames)) {
    const column = mappings.get(fieldName);
    if (!column) {
      continue;
    }

    const fieldValue = readDynamicFieldValue(values, fieldName);
    const value =
      fieldValue === undefined
        ? null
        : serializeDynamicColumnValue(fieldValue);
    const existingAssignment = assignmentsByColumn.get(column);

    if (!existingAssignment || (existingAssignment.value === null && value !== null)) {
      assignmentsByColumn.set(column, {
        column,
        value,
      });
    }
  }

  return Array.from(assignmentsByColumn.values()).sort((left, right) =>
    left.column.localeCompare(right.column),
  );
}

function mapRawRecord(
  row: RawRecordRow,
): RawRecord {
  const payload = parseJsonObject(row.payload_json);
  const dataSourceType = normalizeDataSourceType(
    row.data_source_type,
    inferDataSourceType(payload, row.source),
  );

  return {
    dataSourceType,
    id: row.id,
    recordKey: row.record_key,
    source: row.source,
    version: Number(row.version ?? 0),
    payload,
    payloadColumns: extractDynamicColumns(
      row,
      'payload',
      collectPayloadFieldNames(payload),
    ),
    payloadHash: row.payload_hash,
    receivedAt: row.received_at,
    processedAt: row.processed_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapSecureRecord(
  row: SecureRecordRow,
): SecureRecord {
  const publicData = parseJsonObject(row.public_json);
  const encryptFields = parseStringArray(row.encrypt_fields_json);
  const dataSourceType = normalizeDataSourceType(
    row.data_source_type,
    inferDataSourceType(publicData),
  );

  return {
    dataSourceType,
    id: row.id,
    rawRecordId: row.raw_record_id,
    recordKey: row.record_key,
    version: row.version,
    keyVersion: row.key_version,
    publicData,
    publicColumns: extractDynamicColumns(
      row,
      'public',
      collectPayloadFieldNames(publicData),
    ),
    encryptedData: JSON.parse(row.encrypted_json),
    encryptedColumns: extractDynamicColumns(
      row,
      'encrypted',
      encryptFields,
    ),
    encryptFields,
    fingerprint: row.fingerprint,
    syncedAt: row.synced_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapDownstreamClient(
  row: DownstreamClientRow,
): DownstreamClient {
  const entryKind = row.entry_kind?.trim() || 'sync-client';

  return {
    id: row.id,
    entryKind,
    clientName: row.client_name,
    callbackUrl:
      entryKind === 'sub-report'
        ? row.service_url ?? row.callback_url
        : row.callback_url,
    clientVersion: row.client_version,
    lastSyncVersion: row.last_sync_version,
    lastSeenAt: row.last_seen_at,
    lastPushAt: row.last_push_at,
    lastStatus: row.last_status,
    lastResponseCode: row.last_response_code,
    lastError: row.last_error,
    serviceUrl: row.service_url,
    databackVersion:
      row.databack_version === null || row.databack_version === undefined
        ? null
        : Number(row.databack_version),
    reportCount:
      row.report_count === null || row.report_count === undefined
        ? null
        : Number(row.report_count),
    reportedAt: row.reported_at,
    payload: row.payload_json ? parseJsonObject(row.payload_json) : null,
    lastPullVersion: Number(row.last_pull_version ?? 0),
    lastPullAt: row.last_pull_at,
    lastPullStatus: row.last_pull_status,
    lastPullResponseCode: row.last_pull_response_code,
    lastPullError: row.last_pull_error,
    authFailureCount: Number(row.auth_failure_count ?? 0),
    blacklistedAt: row.blacklisted_at,
    authIssuedAt: row.auth_issued_at,
    authLastSuccessAt: row.auth_last_success_at,
    authLastFailureAt: row.auth_last_failure_at,
  };
}

function normalizeTagLabel(value: string): string {
  return value.replace(/\s+/g, ' ').trim().slice(0, 40);
}

function normalizeTagKey(value: string): string {
  return normalizeTagLabel(value).toLocaleLowerCase('zh-CN');
}

function normalizeTagSlug(value: string): string {
  return normalizeTagKey(value)
    .replace(/[^a-z0-9\u4e00-\u9fa5]+/g, '-')
    .replace(/^-+|-+$/g, '')
    || `tag-${crypto.randomUUID()}`;
}

function mediaTagsContainR18(
  tags: Array<{
    label: string;
    slug?: string;
  }>,
): boolean {
  return tags.some((tag) => (
    (tag.slug ? normalizeTagSlug(tag.slug) : '') === R18_TAG_SLUG
    || normalizeTagKey(tag.label) === R18_TAG_SLUG
  ));
}

function mapMediaTag(row: MediaTagRow): SchoolMediaTag {
  return {
    id: row.id,
    slug: row.slug,
    label: row.label,
    isSystem: Boolean(row.is_system),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function listTagsForMedia(
  db: D1Database,
  mediaId: string,
): Promise<SchoolMediaTag[]> {
  const result = await db.prepare(
    `
      SELECT tags.*
      FROM media_tags AS tags
      INNER JOIN school_media_tags AS links
        ON links.tag_id = tags.id
      WHERE links.media_id = ?
      ORDER BY tags.is_system DESC, tags.label ASC
    `,
  )
    .bind(mediaId)
    .all<MediaTagRow>();

  return (result.results ?? []).map(mapMediaTag);
}

async function mapSchoolMediaRecord(
  db: D1Database,
  row: SchoolMediaRow,
): Promise<SchoolMediaRecord> {
  return {
    id: row.id,
    sourceServiceUrl: row.source_service_url,
    sourceMediaId: row.source_media_id,
    objectKey: row.object_key,
    localObjectKey: row.local_object_key,
    publicUrl: row.public_url,
    mediaType: row.media_type,
    contentType: row.content_type,
    byteSize: Number(row.byte_size),
    fileName: row.file_name,
    schoolName: row.school_name,
    schoolNameNorm: row.school_name_norm,
    schoolAddress: row.school_address,
    province: row.province,
    city: row.city,
    county: row.county,
    isR18: Boolean(row.is_r18),
    status: row.status,
    reviewNote: row.review_note,
    uploadedAt: row.uploaded_at,
    objectSyncedAt: row.object_synced_at,
    reviewedAt: row.reviewed_at,
    sourceUpdatedAt: row.source_updated_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    tags: await listTagsForMedia(db, row.id),
  };
}

async function ensureR18Tag(db: D1Database): Promise<SchoolMediaTag> {
  const now = nowIso();
  await db.prepare(
    `
      INSERT INTO media_tags (
        id,
        slug,
        label,
        normalized_label,
        is_system,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, 1, ?, ?)
      ON CONFLICT(slug) DO UPDATE SET
        label = excluded.label,
        normalized_label = excluded.normalized_label,
        is_system = 1,
        updated_at = excluded.updated_at
    `,
  )
    .bind(R18_TAG_ID, R18_TAG_SLUG, 'R18', 'r18', now, now)
    .run();

  const tag = await db.prepare(
    `
      SELECT *
      FROM media_tags
      WHERE slug = ?
      LIMIT 1
    `,
  )
    .bind(R18_TAG_SLUG)
    .first<MediaTagRow>();

  if (!tag) {
    throw new Error('Failed to initialize R18 media tag.');
  }

  return mapMediaTag(tag);
}

async function ensureMediaTag(
  db: D1Database,
  input: {
    isSystem?: boolean;
    label: string;
    slug?: string;
  },
): Promise<SchoolMediaTag> {
  const label = normalizeTagLabel(input.label);
  if (!label) {
    throw new Error('Media tag is empty.');
  }

  if (normalizeTagKey(label) === R18_TAG_SLUG || input.slug === R18_TAG_SLUG) {
    return ensureR18Tag(db);
  }

  const normalizedLabel = normalizeTagKey(label);
  const slug = normalizeTagSlug(label);
  const now = nowIso();
  await db.prepare(
    `
      INSERT INTO media_tags (
        id,
        slug,
        label,
        normalized_label,
        is_system,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(normalized_label) DO UPDATE SET
        label = excluded.label,
        updated_at = excluded.updated_at
    `,
  )
    .bind(
      `tag:${slug}`,
      slug,
      label,
      normalizedLabel,
      input.isSystem ? 1 : 0,
      now,
      now,
    )
    .run();

  const tag = await db.prepare(
    `
      SELECT *
      FROM media_tags
      WHERE normalized_label = ?
      LIMIT 1
    `,
  )
    .bind(normalizedLabel)
    .first<MediaTagRow>();

  if (!tag) {
    throw new Error('Failed to store media tag.');
  }

  return mapMediaTag(tag);
}

function buildSubReportKey(serviceUrl: string): string {
  return `sub-report:${serviceUrl}`;
}

function buildSubPushUrl(serviceUrl: string): string {
  return new URL(SUB_PUSH_PATH, serviceUrl).toString();
}

function buildSubExportUrl(serviceUrl: string): string {
  return new URL(SUB_EXPORT_PATH, serviceUrl).toString();
}

function readReportedSubVersion(
  row: DownstreamClientRow,
): number {
  return Math.max(
    0,
    Number(row.databack_version ?? 0),
    Number(row.client_version ?? 0),
    Number(row.last_sync_version ?? 0),
  );
}

function readSubPullVersion(
  row: DownstreamClientRow,
): number {
  return Math.max(0, Number(row.last_pull_version ?? 0));
}

function readPushedMainVersion(
  row: DownstreamClientRow,
): number {
  return Math.max(0, Number(row.last_sync_version ?? 0));
}

function readIsoMs(value: string | null | undefined): number | null {
  if (!value) {
    return null;
  }

  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function buildSecureTransferPayload(
  record: SecureRecord,
): SecureTransferPayload {
  return {
    keyVersion: record.keyVersion,
    publicData: record.publicData,
    encryptedData: record.encryptedData,
    encryptFields: record.encryptFields,
    syncedAt: record.syncedAt,
  };
}

function mapSecureRecordToSubPushRecord(
  record: SecureRecord,
): SubPushRecord {
  return {
    dataSourceType: record.dataSourceType,
    recordKey: record.recordKey,
    version: record.version,
    fingerprint: record.fingerprint,
    payload: buildSecureTransferPayload(record),
  };
}

export function isRecognizedSubService(
  serviceName: string,
  serviceWatermark: string,
): boolean {
  return (
    RECOGNIZED_SUB_SERVICES.has(serviceName.trim())
    && serviceWatermark.trim() === NCT_SUB_SERVICE_WATERMARK
  );
}

async function readDownstreamClientRowByServiceUrl(
  db: D1Database,
  serviceUrl: string,
): Promise<DownstreamClientRow | null> {
  return db.prepare(
    `
      SELECT *
      FROM downstream_clients
      WHERE service_url = ?
         OR callback_url = ?
      LIMIT 1
    `,
  )
    .bind(serviceUrl, buildSubReportKey(serviceUrl))
    .first<DownstreamClientRow>();
}

async function readDownstreamClientRowById(
  db: D1Database,
  id: number,
): Promise<DownstreamClientRow | null> {
  return db.prepare(
    `
      SELECT *
      FROM downstream_clients
      WHERE id = ?
      LIMIT 1
    `,
  )
    .bind(id)
    .first<DownstreamClientRow>();
}

async function readDownstreamClientByServiceUrl(
  db: D1Database,
  serviceUrl: string,
): Promise<DownstreamClient | null> {
  const row = await readDownstreamClientRowByServiceUrl(db, serviceUrl);
  return row ? mapDownstreamClient(row) : null;
}

async function readDownstreamClientById(
  db: D1Database,
  id: number,
): Promise<DownstreamClient | null> {
  const row = await readDownstreamClientRowById(db, id);
  return row ? mapDownstreamClient(row) : null;
}

async function recordSubAuthFailure(
  db: D1Database,
  row: DownstreamClientRow,
  maxFailures: number,
  reason: string,
  responseCode: 401 | 403 = 401,
): Promise<{
  blacklisted: boolean;
  currentCount: number;
}> {
  const failureCount = Number(row.auth_failure_count ?? 0) + 1;
  const failedAt = nowIso();
  const blacklistedAt = failureCount >= maxFailures ? failedAt : null;

  await db.prepare(
    `
      UPDATE downstream_clients
      SET auth_failure_count = ?,
          auth_last_failure_at = ?,
          blacklisted_at = COALESCE(blacklisted_at, ?),
          last_response_code = ?,
          last_error = ?
      WHERE id = ?
    `,
  )
    .bind(
      failureCount,
      failedAt,
      blacklistedAt,
      responseCode,
      reason,
      row.id,
    )
    .run();

  return {
    blacklisted: blacklistedAt !== null || row.blacklisted_at !== null,
    currentCount: failureCount,
  };
}

async function verifyRotatingSubAuthToken(
  row: DownstreamClientRow,
  serviceUrl: string,
  token: string,
): Promise<boolean> {
  const credentialSeed = serviceUrl.trim();
  if (!credentialSeed) {
    return false;
  }

  const expectedHash = await sha256(credentialSeed);
  if (row.auth_token_hash?.trim() !== expectedHash) {
    return false;
  }

  return verifyServiceAuthToken(serviceUrl, token);
}

export async function verifySubServiceToken(
  env: Env,
  claimedServiceUrl: string,
  token: string | null,
  maxFailures: number,
  options: {
    allowUnregistered?: boolean;
  } = {},
): Promise<
  | { ok: true; stored: DownstreamClient | null }
  | { ok: false; reason: string; status: 401 | 403 }
> {
  if (!token?.trim()) {
    return {
      ok: false,
      reason: 'Sub service token is required.',
      status: 401,
    };
  }

  const normalizedClaimedServiceUrl = claimedServiceUrl.trim();
  if (!normalizedClaimedServiceUrl) {
    return {
      ok: false,
      reason: 'Sub service URL is required.',
      status: 401,
    };
  }

  const row = await readDownstreamClientRowByServiceUrl(env.DB, normalizedClaimedServiceUrl);
  if (!row) {
    if (
      options.allowUnregistered
      && await verifyServiceAuthToken(
        normalizedClaimedServiceUrl,
        token.trim(),
      )
    ) {
      return {
        ok: true,
        stored: null,
      };
    }

    return {
      ok: false,
      reason: 'Sub service is not registered.',
      status: 401,
    };
  }

  if (row.blacklisted_at) {
    return {
      ok: false,
      reason: 'This sub service has been blacklisted.',
      status: 403,
    };
  }

  const normalizedStoredServiceUrl = row.service_url?.trim() || '';
  if (
    normalizedClaimedServiceUrl
    && normalizedStoredServiceUrl
    && normalizedClaimedServiceUrl !== normalizedStoredServiceUrl
  ) {
    const failure = await recordSubAuthFailure(
      env.DB,
      row,
      maxFailures,
      'Sub service identity does not match the claimed service URL.',
      403,
    );
    return {
      ok: false,
      reason: failure.blacklisted
        ? 'Sub service identity does not match the claimed service URL and this service is now blacklisted.'
        : 'Sub service identity does not match the claimed service URL.',
      status: 403,
    };
  }

  const verifiedServiceUrl = normalizedStoredServiceUrl || normalizedClaimedServiceUrl;
  if (!(await verifyRotatingSubAuthToken(row, verifiedServiceUrl, token.trim()))) {
    return {
      ok: false,
      reason: 'Sub service token is invalid.',
      status: 401,
    };
  }

  const authenticatedAt = nowIso();
  await env.DB.prepare(
    `
      UPDATE downstream_clients
      SET auth_failure_count = 0,
          auth_last_success_at = ?,
          last_seen_at = ?,
          last_error = NULL
      WHERE id = ?
    `,
  )
    .bind(
      authenticatedAt,
      authenticatedAt,
      row.id,
    )
    .run();

  const stored = await readDownstreamClientById(env.DB, row.id);
  if (!stored) {
    throw new Error('Failed to read back sub auth state.');
  }

  return {
    ok: true,
    stored,
  };
}

export async function ingestSubFormRecords(
  env: Env,
  request: SubFormRecordsRequest,
): Promise<SubFormRecordResult[]> {
  const results: SubFormRecordResult[] = [];

  for (const record of request.records) {
    const [ingested] = await ingestRecords(env, [
      {
        dataSourceType: 'questionnaire',
        payload: record.payload,
        recordKey: record.recordKey,
        source: `${SUB_FORM_SOURCE_PREFIX}${request.serviceUrl}`,
      },
    ]);

    results.push({
      databackFingerprint: ingested.fingerprint,
      motherVersion: ingested.version,
      recordKey: record.recordKey,
      updated: ingested.updated,
    });
  }

  return results;
}

export async function ingestSubMediaRecords(
  env: Env,
  request: SubMediaRecordsRequest,
): Promise<SubMediaRecordResult[]> {
  const results: SubMediaRecordResult[] = [];

  for (const record of request.records) {
    const now = nowIso();
    const recordIsR18 = mediaTagsContainR18(record.tags);
    const existing = await env.DB.prepare(
      `
        SELECT *
        FROM school_media
        WHERE source_service_url = ?
          AND source_media_id = ?
        LIMIT 1
      `,
    )
      .bind(request.serviceUrl, record.id)
      .first<SchoolMediaRow>();
    const mediaId = existing?.id ?? crypto.randomUUID();
    const previousFingerprint = existing
      ? await sha256(stableStringify({
          byteSize: existing.byte_size,
          city: existing.city,
          contentType: existing.content_type,
          county: existing.county,
          fileName: existing.file_name,
          isR18: Boolean(existing.is_r18),
          objectKey: existing.object_key,
          province: existing.province,
          publicUrl: existing.local_object_key ? record.publicUrl : existing.public_url,
          schoolAddress: existing.school_address,
          schoolName: existing.school_name,
          schoolNameNorm: existing.school_name_norm,
          sourceUpdatedAt: existing.source_updated_at,
          uploadedAt: existing.uploaded_at,
        }))
      : '';
    const nextFingerprint = await sha256(stableStringify({
      ...record,
      isR18: recordIsR18,
    }));
    const updated = !existing || previousFingerprint !== nextFingerprint;

    await env.DB.prepare(
      `
        INSERT INTO school_media (
          id,
          source_service_url,
          source_media_id,
          object_key,
          public_url,
          media_type,
          content_type,
          byte_size,
          file_name,
          school_name,
          school_name_norm,
          school_address,
          province,
          city,
          county,
          is_r18,
          status,
          uploaded_at,
          source_updated_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_review', ?, ?, ?, ?)
        ON CONFLICT(source_service_url, source_media_id) DO UPDATE SET
          object_key = excluded.object_key,
          public_url = CASE
            WHEN school_media.local_object_key IS NOT NULL
              THEN school_media.public_url
            ELSE excluded.public_url
          END,
          media_type = excluded.media_type,
          content_type = excluded.content_type,
          byte_size = excluded.byte_size,
          file_name = excluded.file_name,
          school_name = excluded.school_name,
          school_name_norm = excluded.school_name_norm,
          school_address = excluded.school_address,
          province = excluded.province,
          city = excluded.city,
          county = excluded.county,
          is_r18 = excluded.is_r18,
          uploaded_at = excluded.uploaded_at,
          source_updated_at = excluded.source_updated_at,
          updated_at = excluded.updated_at
      `,
    )
      .bind(
        mediaId,
        request.serviceUrl,
        record.id,
        record.objectKey,
        record.publicUrl,
        record.mediaType,
        record.contentType,
        Math.max(0, Math.trunc(Number(record.byteSize))),
        record.fileName,
        record.schoolName,
        record.schoolNameNorm,
        record.schoolAddress,
        record.province,
        record.city,
        record.county,
        recordIsR18 ? 1 : 0,
        record.uploadedAt,
        record.updatedAt,
        now,
        now,
      )
      .run();

    await env.DB.prepare(
      `
        DELETE FROM school_media_tags
        WHERE media_id = ?
      `,
    )
      .bind(mediaId)
      .run();

    const tags = [];
    if (recordIsR18) {
      tags.push(await ensureR18Tag(env.DB));
    }
    for (const tag of record.tags) {
      const stored = await ensureMediaTag(env.DB, {
        isSystem: tag.isSystem,
        label: tag.label,
        slug: tag.slug,
      });
      if (!tags.some((item) => item.id === stored.id)) {
        tags.push(stored);
      }
    }

    for (const tag of tags) {
      await env.DB.prepare(
        `
          INSERT OR IGNORE INTO school_media_tags (
            media_id,
            tag_id
          )
          VALUES (?, ?)
        `,
      )
        .bind(mediaId, tag.id)
        .run();
    }

    results.push({
      mediaId: record.id,
      updated,
    });
  }

  return results;
}

export async function listRawRecords(
  db: D1Database,
  limit?: number,
): Promise<RawRecord[]> {
  const statement =
    limit === undefined
      ? db.prepare(
          `
            SELECT *
            FROM raw_records
            ORDER BY updated_at DESC
          `,
        )
      : db
          .prepare(
            `
              SELECT *
              FROM raw_records
              ORDER BY updated_at DESC
              LIMIT ?
            `,
          )
          .bind(limit);
  const result = await statement.all<RawRecordRow>();

  return (result.results ?? []).map(mapRawRecord);
}

export async function listSecureRecords(
  db: D1Database,
  limit?: number,
): Promise<SecureRecord[]> {
  const statement =
    limit === undefined
      ? db.prepare(
          `
            SELECT *
            FROM secure_records
            ORDER BY version DESC, updated_at DESC
          `,
        )
      : db
          .prepare(
            `
              SELECT *
              FROM secure_records
              ORDER BY version DESC, updated_at DESC
              LIMIT ?
            `,
          )
          .bind(limit);
  const result = await statement.all<SecureRecordRow>();

  return (result.results ?? []).map(mapSecureRecord);
}

export async function listDownstreamClients(
  db: D1Database,
  limit?: number,
): Promise<DownstreamClient[]> {
  const statement =
    limit === undefined
      ? db.prepare(
          `
            SELECT *
            FROM downstream_clients
            ORDER BY last_seen_at DESC
          `,
        )
      : db
          .prepare(
            `
              SELECT *
              FROM downstream_clients
              ORDER BY last_seen_at DESC
              LIMIT ?
            `,
          )
          .bind(limit);
  const result = await statement.all<DownstreamClientRow>();

  return (result.results ?? []).map(mapDownstreamClient);
}

export async function ingestRecords(
  env: Env,
  records: IngestRecordInput[],
): Promise<IngestResult[]> {
  if (!records.length) {
    return [];
  }

  // Each ingest keeps the raw table and the published secure table in lockstep, expanding dynamic columns as fields evolve.
  const keyVersion = CURRENT_ENCRYPTION_KEY_VERSION;
  const results: IngestResult[] = [];

  for (const rawInput of records) {
    const payload = toJsonObject(rawInput.payload);
    const recordKey = readRecordKey(rawInput);
    const source = rawInput.source?.trim() || 'downstream';
    const dataSourceType = normalizeDataSourceType(
      rawInput.dataSourceType,
      inferDataSourceType(payload, source),
    );
    const payloadJson = stableStringify(payload);
    const fingerprint = await computeRecordContentFingerprint(payload);
    const payloadHash = fingerprint;
    const receivedAt = nowIso();
    const existingRaw = await env.DB.prepare(
      `
        SELECT *
        FROM raw_records
        WHERE record_key = ?
      `,
    )
      .bind(recordKey)
      .first<RawRecordRow>();
    const existingSecure = await env.DB.prepare(
      `
        SELECT *
        FROM secure_records
        WHERE record_key = ?
      `,
    )
      .bind(recordKey)
      .first<SecureRecordRow>();
    const previousPayload = existingRaw
      ? parseJsonObject(existingRaw.payload_json)
      : {};
    const previousFieldNames = Object.keys(previousPayload);
    const previousEncryptFields = existingSecure
      ? parseStringArray(existingSecure.encrypt_fields_json)
      : [];
    const previousEncryptedFieldSet = new Set(previousEncryptFields);
    const previousPublicFieldNames = previousFieldNames.filter(
      (fieldName) => !previousEncryptedFieldSet.has(fieldName),
    );
    const previousEncryptedFieldNames = previousFieldNames.filter(
      (fieldName) => previousEncryptedFieldSet.has(fieldName),
    );
    const encryptFields = Array.from(
      new Set(
        (rawInput.encryptFields?.length
          ? rawInput.encryptFields
          : getDefaultEncryptFields(env)
        ).map((field) => field.trim()).filter(Boolean),
      ),
    );
    const { publicData, secretData } = partitionPayload(
      payload,
      encryptFields,
    );
    const rawFieldNames = collectPayloadFieldNames(
      previousPayload,
      payload,
    );
    const previousPublicPayload = previousPublicFieldNames.reduce<JsonObject>(
      (accumulator, fieldName) => {
        if (hasOwn(previousPayload, fieldName)) {
          accumulator[fieldName] = previousPayload[fieldName];
        }

        return accumulator;
      },
      {},
    );
    const publicFieldNames = collectPayloadFieldNames(
      previousPublicPayload,
      publicData,
    );
    const encryptedFieldNames = collectFieldNames(
      previousEncryptedFieldNames,
      Object.keys(secretData),
    );
    const rawColumnMappings = await ensureDynamicColumns(
      env.DB,
      'raw_records',
      'payload',
      rawFieldNames,
    );
    const publicColumnMappings = await ensureDynamicColumns(
      env.DB,
      'secure_records',
      'public',
      publicFieldNames,
    );
    const encryptedColumnMappings = await ensureDynamicColumns(
      env.DB,
      'secure_records',
      'encrypted',
      encryptedFieldNames,
    );
    const currentVersion = await getCurrentVersion(env.DB);
    const hasChanged = existingSecure?.fingerprint !== fingerprint;
    const dataSourceTypeChanged = existingSecure?.data_source_type !== dataSourceType;
    const nextVersion = existingSecure
      ? hasChanged
        ? deriveRecordContentVersion(currentVersion, fingerprint)
        : existingSecure.version
      : deriveRecordContentVersion(currentVersion, fingerprint);
    const publicJson = stableStringify(publicData);
    const encryptedEnvelope = await encryptObject(
      secretData,
      env.ENCRYPTION_KEY,
    );
    const encryptedJson = stableStringify(encryptedEnvelope);
    const encryptedColumnValues: JsonObject = {};

    for (const [fieldName, fieldValue] of Object.entries(secretData)) {
      encryptedColumnValues[fieldName] = stableStringify(
        await encryptObject(
          { [fieldName]: fieldValue },
          env.ENCRYPTION_KEY,
        ),
      );
    }

    const rawRecordId = existingRaw?.id ?? crypto.randomUUID();
    const rawDynamicAssignments = buildDynamicAssignments(
      rawColumnMappings,
      rawFieldNames,
      payload,
    );

    if (existingRaw) {
      const updateColumns = [
        'source',
        'data_source_type',
        'version',
        'payload_json',
        'payload_hash',
        'received_at',
        'updated_at',
        ...rawDynamicAssignments.map(
          (assignment) => assignment.column,
        ),
      ];
      const updateValues = [
        source,
        dataSourceType,
        nextVersion,
        payloadJson,
        payloadHash,
        receivedAt,
        receivedAt,
        ...rawDynamicAssignments.map(
          (assignment) => assignment.value,
        ),
        rawRecordId,
      ];

      await env.DB.prepare(
        buildUpdateStatement(
          'raw_records',
          updateColumns,
          'id',
        ),
      )
        .bind(...updateValues)
        .run();
    } else {
      const insertColumns = [
        'id',
        'record_key',
        'source',
        'data_source_type',
        'version',
        'payload_json',
        'payload_hash',
        'received_at',
        'created_at',
        'updated_at',
        ...rawDynamicAssignments.map(
          (assignment) => assignment.column,
        ),
      ];
      const insertValues = [
        rawRecordId,
        recordKey,
        source,
        dataSourceType,
        nextVersion,
        payloadJson,
        payloadHash,
        receivedAt,
        receivedAt,
        receivedAt,
        ...rawDynamicAssignments.map(
          (assignment) => assignment.value,
        ),
      ];

      await env.DB.prepare(
        buildInsertStatement(
          'raw_records',
          insertColumns,
        ),
      )
        .bind(...insertValues)
        .run();
    }

    const secureRecordId = existingSecure?.id ?? crypto.randomUUID();
    const publicDynamicAssignments = buildDynamicAssignments(
      publicColumnMappings,
      publicFieldNames,
      publicData,
    );
    const encryptedDynamicAssignments = buildDynamicAssignments(
      encryptedColumnMappings,
      encryptedFieldNames,
      encryptedColumnValues,
    );

    if (!existingSecure) {
      const insertColumns = [
        'id',
        'raw_record_id',
        'record_key',
        'data_source_type',
        'version',
        'key_version',
        'public_json',
        'encrypted_json',
        'encrypt_fields_json',
        'fingerprint',
        'created_at',
        'updated_at',
        ...publicDynamicAssignments.map(
          (assignment) => assignment.column,
        ),
        ...encryptedDynamicAssignments.map(
          (assignment) => assignment.column,
        ),
      ];
      const insertValues = [
        secureRecordId,
        rawRecordId,
        recordKey,
        dataSourceType,
        nextVersion,
        keyVersion,
        publicJson,
        encryptedJson,
        stableStringify(encryptFields),
        fingerprint,
        receivedAt,
        receivedAt,
        ...publicDynamicAssignments.map(
          (assignment) => assignment.value,
        ),
        ...encryptedDynamicAssignments.map(
          (assignment) => assignment.value,
        ),
      ];

      await env.DB.prepare(
        buildInsertStatement(
          'secure_records',
          insertColumns,
        ),
      )
        .bind(...insertValues)
        .run();
    } else if (hasChanged || dataSourceTypeChanged) {
      const updateColumns = [
        'raw_record_id',
        'data_source_type',
        'version',
        'key_version',
        'public_json',
        'encrypted_json',
        'encrypt_fields_json',
        'fingerprint',
        'updated_at',
        ...publicDynamicAssignments.map(
          (assignment) => assignment.column,
        ),
        ...encryptedDynamicAssignments.map(
          (assignment) => assignment.column,
        ),
      ];
      const updateValues = [
        rawRecordId,
        dataSourceType,
        nextVersion,
        keyVersion,
        publicJson,
        encryptedJson,
        stableStringify(encryptFields),
        fingerprint,
        receivedAt,
        ...publicDynamicAssignments.map(
          (assignment) => assignment.value,
        ),
        ...encryptedDynamicAssignments.map(
          (assignment) => assignment.value,
        ),
        secureRecordId,
      ];

      await env.DB.prepare(
        buildUpdateStatement(
          'secure_records',
          updateColumns,
          'id',
        ),
      )
        .bind(...updateValues)
        .run();
    }

    await env.DB.prepare(
      `
        UPDATE raw_records
        SET processed_at = ?,
            updated_at = ?
        WHERE id = ?
      `,
    )
      .bind(receivedAt, receivedAt, rawRecordId)
      .run();

    results.push({
      recordKey,
      rawRecordId,
      secureRecordId,
      version: nextVersion,
      fingerprint,
      updated: !existingSecure || hasChanged || dataSourceTypeChanged,
    });
  }

  return results;
}

export async function rebuildSecureRecords(
  env: Env,
): Promise<IngestResult[]> {
  const rawRecords = await listRawRecords(env.DB);

  return ingestRecords(
    env,
    rawRecords.map((record) => ({
      dataSourceType: record.dataSourceType,
      recordKey: record.recordKey,
      source: record.source,
      payload: record.payload,
    })),
  );
}

export async function getPublishedPayload(
  db: D1Database,
  currentVersion: number,
  requestedVersion: number,
  mode: 'full' | 'delta',
): Promise<SyncPayload> {
  const query =
    mode === 'delta'
      ? `
          SELECT *
          FROM secure_records
          WHERE version > ?
          ORDER BY version ASC
        `
      : `
          SELECT *
          FROM secure_records
          ORDER BY version ASC
        `;

  const statement = db.prepare(query);
  const result =
    mode === 'delta'
      ? await statement.bind(requestedVersion).all<SecureRecordRow>()
      : await statement.all<SecureRecordRow>();

  const records = (result.results ?? []).map(mapSecureRecord);

  return {
    mode,
    previousVersion: requestedVersion,
    currentVersion,
    totalRecords: records.length,
    records,
    generatedAt: nowIso(),
  };
}

async function buildSubPushPayload(
  db: D1Database,
  currentVersion: number,
  previousVersion: number,
): Promise<SubPushPayload> {
  const published = await getPublishedPayload(
    db,
    currentVersion,
    previousVersion,
    'delta',
  );

  return {
    service: 'NCT API SQL',
    mode: published.mode,
    previousVersion: published.previousVersion,
    currentVersion: published.currentVersion,
    totalRecords: published.totalRecords,
    records: published.records.map(mapSecureRecordToSubPushRecord),
    generatedAt: published.generatedAt,
  };
}

function isSecureTransferPayload(
  value: unknown,
): value is SecureTransferPayload {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const candidate = value as Record<string, unknown>;
  const encryptedData = candidate.encryptedData as Record<string, unknown> | undefined;
  return (
    typeof candidate.keyVersion === 'number'
    && Number.isFinite(candidate.keyVersion)
    && !!candidate.publicData
    && typeof candidate.publicData === 'object'
    && !Array.isArray(candidate.publicData)
    && !!encryptedData
    && typeof encryptedData === 'object'
    && !Array.isArray(encryptedData)
    && encryptedData.algorithm === 'AES-GCM'
    && typeof encryptedData.iv === 'string'
    && typeof encryptedData.ciphertext === 'string'
    && Array.isArray(candidate.encryptFields)
    && candidate.encryptFields.every((field) => typeof field === 'string')
    && (typeof candidate.syncedAt === 'string' || candidate.syncedAt === null)
  );
}

function isPlainJsonObject(value: unknown): value is JsonObject {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function parseSubDatabackExportFile(
  value: unknown,
): SubDatabackExportFile {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Sub export file must be a JSON object.');
  }

  const candidate = value as Record<string, unknown>;
  if (
    typeof candidate.service !== 'string'
    || typeof candidate.serviceUrl !== 'string'
    || typeof candidate.afterVersion !== 'number'
    || (candidate.currentVersion !== null
      && typeof candidate.currentVersion !== 'number')
    || typeof candidate.exportedAt !== 'string'
    || typeof candidate.totalRecords !== 'number'
    || !Array.isArray(candidate.records)
  ) {
    throw new Error('Sub export file is missing required fields.');
  }

  const records = candidate.records.map((record) => {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      throw new Error('Sub export record must be a JSON object.');
    }

    const entry = record as Record<string, unknown>;
    if (
      typeof entry.recordKey !== 'string'
      || typeof entry.version !== 'number'
      || typeof entry.fingerprint !== 'string'
      || typeof entry.updatedAt !== 'string'
      || (
        !isSecureTransferPayload(entry.payload)
        && !isPlainJsonObject(entry.payload)
      )
      || (
        entry.payloadEncryptionState !== 'plain-json'
        && entry.payloadEncryptionState !== 'secure-transfer'
      )
    ) {
      throw new Error('Sub export record has an invalid shape.');
    }

    return {
      payload: entry.payload,
      payloadEncryptionState: entry.payloadEncryptionState as SubDatabackExportFile['records'][number]['payloadEncryptionState'],
      recordKey: entry.recordKey,
      version: entry.version,
      fingerprint: entry.fingerprint,
      updatedAt: entry.updatedAt,
    };
  });

  return {
    service: candidate.service,
    serviceUrl: candidate.serviceUrl,
    afterVersion: candidate.afterVersion,
    currentVersion: candidate.currentVersion,
    exportedAt: candidate.exportedAt,
    totalRecords: candidate.totalRecords,
    records,
  };
}

async function computeSecureTransferFingerprint(
  env: Env,
  payload: SecureTransferPayload,
): Promise<{
  fingerprint: string;
  secretData: JsonObject;
}> {
  const secretData = await decryptObject(payload.encryptedData, env.ENCRYPTION_KEY);

  return {
    fingerprint: await computeRecordContentFingerprint({
      ...payload.publicData,
      ...secretData,
    }),
    secretData,
  };
}

async function upsertRawRecord(
  env: Env,
  input: {
    dataSourceType?: DataSourceType;
    fingerprint?: string;
    payload: JsonObject;
    recordKey: string;
    receivedAt?: string;
    source: string;
    version?: number;
  },
): Promise<{
  id: string;
}> {
  const payload = toJsonObject(input.payload);
  const dataSourceType = normalizeDataSourceType(
    input.dataSourceType,
    inferDataSourceType(payload, input.source),
  );
  const payloadJson = stableStringify(payload);
  const payloadHash = input.fingerprint ?? await computeRecordContentFingerprint(payload);
  const inputVersion = Number(input.version);
  const version =
    input.version === undefined || !Number.isFinite(inputVersion)
      ? deriveRecordContentVersion(await getCurrentVersion(env.DB), payloadHash)
      : Math.max(0, Math.trunc(inputVersion));
  const receivedAt = input.receivedAt ?? nowIso();
  const existingRaw = await env.DB.prepare(
    `
      SELECT *
      FROM raw_records
      WHERE record_key = ?
    `,
  )
    .bind(input.recordKey)
    .first<RawRecordRow>();
  const previousPayload = existingRaw
    ? parseJsonObject(existingRaw.payload_json)
    : {};
  const rawFieldNames = collectPayloadFieldNames(
    previousPayload,
    payload,
  );
  const rawColumnMappings = await ensureDynamicColumns(
    env.DB,
    'raw_records',
    'payload',
    rawFieldNames,
  );
  const rawDynamicAssignments = buildDynamicAssignments(
    rawColumnMappings,
    rawFieldNames,
    payload,
  );
  const rawRecordId = existingRaw?.id ?? crypto.randomUUID();

  if (existingRaw) {
    const updateColumns = [
      'source',
      'data_source_type',
      'version',
      'payload_json',
      'payload_hash',
      'received_at',
      'updated_at',
      ...rawDynamicAssignments.map((assignment) => assignment.column),
    ];
    const updateValues = [
      input.source,
      dataSourceType,
      version,
      payloadJson,
      payloadHash,
      receivedAt,
      receivedAt,
      ...rawDynamicAssignments.map((assignment) => assignment.value),
      rawRecordId,
    ];

    await env.DB.prepare(
      buildUpdateStatement('raw_records', updateColumns, 'id'),
    )
      .bind(...updateValues)
      .run();
  } else {
    const insertColumns = [
      'id',
      'record_key',
      'source',
      'data_source_type',
      'version',
      'payload_json',
      'payload_hash',
      'received_at',
      'created_at',
      'updated_at',
      ...rawDynamicAssignments.map((assignment) => assignment.column),
    ];
    const insertValues = [
      rawRecordId,
      input.recordKey,
      input.source,
      dataSourceType,
      version,
      payloadJson,
      payloadHash,
      receivedAt,
      receivedAt,
      receivedAt,
      ...rawDynamicAssignments.map((assignment) => assignment.value),
    ];

    await env.DB.prepare(
      buildInsertStatement('raw_records', insertColumns),
    )
      .bind(...insertValues)
      .run();
  }

  await env.DB.prepare(
    `
      UPDATE raw_records
      SET processed_at = ?,
          updated_at = ?
      WHERE id = ?
    `,
  )
    .bind(receivedAt, receivedAt, rawRecordId)
    .run();

  return {
    id: rawRecordId,
  };
}

async function upsertRecoveredSecureTransferRecord(
  env: Env,
  serviceUrl: string,
  record: SubDatabackExportFile['records'][number],
): Promise<boolean> {
  if (!isSecureTransferPayload(record.payload)) {
    throw new Error('Recovered secure transfer payload is invalid.');
  }

  const { fingerprint, secretData } = await computeSecureTransferFingerprint(env, record.payload);
  if (fingerprint !== record.fingerprint) {
    throw new Error(
      `Fingerprint mismatch while importing ${record.recordKey} from ${serviceUrl}.`,
    );
  }

  const rawPayload = {
    ...record.payload.publicData,
    ...secretData,
  };
  const dataSourceType = normalizeDataSourceType(
    record.dataSourceType,
    inferDataSourceType(record.payload.publicData, `${SUB_RECOVERY_SOURCE_PREFIX}${serviceUrl}`),
  );
  const receivedAt = typeof record.updatedAt === 'string' ? record.updatedAt : nowIso();
  const rawRecord = await upsertRawRecord(env, {
    dataSourceType,
    fingerprint: record.fingerprint,
    payload: rawPayload,
    recordKey: record.recordKey,
    receivedAt,
    source: `${SUB_RECOVERY_SOURCE_PREFIX}${serviceUrl}`,
    version: Number(record.version),
  });
  const existingSecure = await env.DB.prepare(
    `
      SELECT *
      FROM secure_records
      WHERE record_key = ?
    `,
  )
    .bind(record.recordKey)
    .first<SecureRecordRow>();
  const existingVersion = Number(existingSecure?.version ?? 0);
  const shouldUpdate = !existingSecure
    || Number(record.version) > existingVersion
    || (
      Number(record.version) === existingVersion
      && existingSecure?.fingerprint !== record.fingerprint
    );

  if (!shouldUpdate) {
    return false;
  }

  const previousPublicData = existingSecure
    ? parseJsonObject(existingSecure.public_json)
    : {};
  const previousEncryptFields = existingSecure
    ? parseStringArray(existingSecure.encrypt_fields_json)
    : [];
  const previousEncryptedFieldSet = new Set(previousEncryptFields);
  const previousEncryptedFieldNames = Object.keys({
    ...secretData,
  }).filter((fieldName) => previousEncryptedFieldSet.has(fieldName));
  const publicFieldNames = collectPayloadFieldNames(
    previousPublicData,
    record.payload.publicData,
  );
  const encryptedFieldNames = collectFieldNames(
    previousEncryptedFieldNames,
    record.payload.encryptFields,
  );
  const publicColumnMappings = await ensureDynamicColumns(
    env.DB,
    'secure_records',
    'public',
    publicFieldNames,
  );
  const encryptedColumnMappings = await ensureDynamicColumns(
    env.DB,
    'secure_records',
    'encrypted',
    encryptedFieldNames,
  );
  const encryptedColumnValues: JsonObject = {};
  for (const [fieldName, fieldValue] of Object.entries(secretData)) {
    encryptedColumnValues[fieldName] = stableStringify(
      await encryptObject(
        { [fieldName]: fieldValue },
        env.ENCRYPTION_KEY,
      ),
    );
  }

  const publicDynamicAssignments = buildDynamicAssignments(
    publicColumnMappings,
    publicFieldNames,
    record.payload.publicData,
  );
  const encryptedDynamicAssignments = buildDynamicAssignments(
    encryptedColumnMappings,
    encryptedFieldNames,
    encryptedColumnValues,
  );
  const secureRecordId = existingSecure?.id ?? crypto.randomUUID();
  const publicJson = stableStringify(record.payload.publicData);
  const encryptedJson = stableStringify(record.payload.encryptedData);

  if (existingSecure) {
    const updateColumns = [
      'raw_record_id',
      'data_source_type',
      'version',
      'key_version',
      'public_json',
      'encrypted_json',
      'encrypt_fields_json',
      'fingerprint',
      'synced_at',
      'updated_at',
      ...publicDynamicAssignments.map((assignment) => assignment.column),
      ...encryptedDynamicAssignments.map((assignment) => assignment.column),
    ];
    const updateValues = [
      rawRecord.id,
      dataSourceType,
      Number(record.version),
      Math.max(1, Number(record.payload.keyVersion)),
      publicJson,
      encryptedJson,
      stableStringify(record.payload.encryptFields),
      record.fingerprint,
      record.payload.syncedAt,
      receivedAt,
      ...publicDynamicAssignments.map((assignment) => assignment.value),
      ...encryptedDynamicAssignments.map((assignment) => assignment.value),
      secureRecordId,
    ];

    await env.DB.prepare(
      buildUpdateStatement('secure_records', updateColumns, 'id'),
    )
      .bind(...updateValues)
      .run();
  } else {
    const insertColumns = [
      'id',
      'raw_record_id',
      'record_key',
      'data_source_type',
      'version',
      'key_version',
      'public_json',
      'encrypted_json',
      'encrypt_fields_json',
      'fingerprint',
      'synced_at',
      'created_at',
      'updated_at',
      ...publicDynamicAssignments.map((assignment) => assignment.column),
      ...encryptedDynamicAssignments.map((assignment) => assignment.column),
    ];
    const insertValues = [
      secureRecordId,
      rawRecord.id,
      record.recordKey,
      dataSourceType,
      Number(record.version),
      Math.max(1, Number(record.payload.keyVersion)),
      publicJson,
      encryptedJson,
      stableStringify(record.payload.encryptFields),
      record.fingerprint,
      record.payload.syncedAt,
      receivedAt,
      receivedAt,
      ...publicDynamicAssignments.map((assignment) => assignment.value),
      ...encryptedDynamicAssignments.map((assignment) => assignment.value),
    ];

    await env.DB.prepare(
      buildInsertStatement('secure_records', insertColumns),
    )
      .bind(...insertValues)
      .run();
  }

  return true;
}

async function importSubDatabackExportFile(
  env: Env,
  serviceUrl: string,
  exportFile: SubDatabackExportFile,
): Promise<{
  receivedCount: number;
  importedCount: number;
  updatedCount: number;
  skippedCount: number;
  highestPulledVersion: number;
}> {
  if (exportFile.serviceUrl.trim() !== serviceUrl) {
    throw new Error(
      `Sub export service URL mismatch: expected ${serviceUrl}, got ${exportFile.serviceUrl.trim()}.`,
    );
  }

  let updatedCount = 0;
  let skippedCount = 0;
  let highestPulledVersion = Math.max(0, exportFile.afterVersion);

  for (const record of exportFile.records) {
    highestPulledVersion = Math.max(
      highestPulledVersion,
      Math.max(0, Number(record.version)),
    );
    const existingSecure = await env.DB.prepare(
      `
        SELECT fingerprint
        FROM secure_records
        WHERE record_key = ?
      `,
    )
      .bind(record.recordKey)
      .first<{ fingerprint: string | null }>();

    if (
      record.payloadEncryptionState === 'secure-transfer'
      && existingSecure?.fingerprint === record.fingerprint
    ) {
      skippedCount += 1;
      continue;
    }

    if (record.payloadEncryptionState === 'secure-transfer') {
      const updated = await upsertRecoveredSecureTransferRecord(
        env,
        serviceUrl,
        record,
      );
      if (updated) {
        updatedCount += 1;
      } else {
        skippedCount += 1;
      }
      continue;
    }

    const payload = toJsonObject(record.payload);
    const fingerprint = await computeRecordContentFingerprint(payload);
    if (fingerprint !== record.fingerprint) {
      throw new Error(
        `Fingerprint mismatch while importing ${record.recordKey} from ${serviceUrl}.`,
      );
    }

    const [result] = await ingestRecords(env, [
      {
        dataSourceType: normalizeDataSourceType(
          record.dataSourceType,
          inferDataSourceType(payload, `${SUB_RECOVERY_SOURCE_PREFIX}${serviceUrl}`),
        ),
        payload,
        recordKey: record.recordKey,
        source: `${SUB_RECOVERY_SOURCE_PREFIX}${serviceUrl}`,
      },
    ]);

    if (result?.updated) {
      updatedCount += 1;
    } else {
      skippedCount += 1;
    }
  }

  return {
    receivedCount: exportFile.records.length,
    importedCount: exportFile.records.length,
    updatedCount,
    skippedCount,
    highestPulledVersion,
  };
}

export async function getSubReportThrottleState(
  db: D1Database,
  serviceUrl: string,
  minIntervalMs: number,
): Promise<{
  retryAfterMs: number;
  lastSeenAt: string | null;
} | null> {
  if (minIntervalMs <= 0) {
    return null;
  }

  const existing = await db.prepare(
    `
      SELECT last_seen_at
      FROM downstream_clients
      WHERE callback_url = ?
    `,
  )
    .bind(buildSubReportKey(serviceUrl))
    .first<{ last_seen_at: string | null }>();

  const lastSeenMs = readIsoMs(existing?.last_seen_at);
  if (lastSeenMs === null) {
    return null;
  }

  const elapsed = Date.now() - lastSeenMs;
  if (elapsed >= minIntervalMs) {
    return null;
  }

  return {
    retryAfterMs: Math.max(0, minIntervalMs - elapsed),
    lastSeenAt: existing?.last_seen_at ?? null,
  };
}

export async function recordSyncRequest(
  env: Env,
  request: SyncRequest,
): Promise<{
  currentVersion: number;
  payload: SyncPayload | null;
  pushed: boolean;
  downstreamStatus: string;
  responseCode: number | null;
}> {
  const currentVersion = await getCurrentVersion(env.DB);
  const seenAt = nowIso();
  const clientName = request.clientName?.trim() || null;
  const currentClientVersion = Math.max(0, Number(request.currentVersion ?? 0));

  await env.DB.prepare(
    `
      INSERT INTO downstream_clients (
        entry_kind,
        client_name,
        callback_url,
        client_version,
        last_sync_version,
        last_seen_at,
        last_status
      )
      VALUES ('sync-client', ?, ?, ?, 0, ?, 'pending')
      ON CONFLICT(callback_url) DO UPDATE SET
        entry_kind = 'sync-client',
        client_name = excluded.client_name,
        client_version = excluded.client_version,
        last_seen_at = excluded.last_seen_at,
        service_url = NULL,
        databack_version = NULL,
        report_count = 0,
        reported_at = NULL,
        payload_json = NULL
    `,
  )
    .bind(
      clientName,
      request.callbackUrl,
      currentClientVersion,
      seenAt,
    )
    .run();

  if (currentClientVersion >= currentVersion) {
    await env.DB.prepare(
      `
        UPDATE downstream_clients
        SET last_status = 'up-to-date',
            last_error = NULL,
            last_response_code = 204
        WHERE callback_url = ?
      `,
    )
      .bind(request.callbackUrl)
      .run();

    return {
      currentVersion,
      payload: null,
      pushed: false,
      downstreamStatus: 'up-to-date',
      responseCode: 204,
    };
  }

  const mode = request.mode === 'delta' ? 'delta' : 'full';
  const payload = await getPublishedPayload(
    env.DB,
    currentVersion,
    currentClientVersion,
    mode,
  );

  let responseCode: number | null = null;
  let downstreamStatus = 'queued';
  let pushed = false;
  let lastError: string | null = null;

  try {
    const response = await fetch(request.callbackUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    responseCode = response.status;
    pushed = response.ok;
    downstreamStatus = response.ok ? 'pushed' : 'push-failed';
    if (!response.ok) {
      lastError = await response.text();
    }
  } catch (error) {
    pushed = false;
    downstreamStatus = 'push-error';
    responseCode = null;
    lastError = error instanceof Error ? error.message : 'Unknown sync error';
  }

  await env.DB.prepare(
    `
      UPDATE downstream_clients
      SET last_sync_version = ?,
          last_push_at = ?,
          last_status = ?,
          last_response_code = ?,
          last_error = ?
      WHERE callback_url = ?
    `,
  )
    .bind(
      pushed ? currentVersion : currentClientVersion,
      seenAt,
      downstreamStatus,
      responseCode,
      lastError,
      request.callbackUrl,
    )
    .run();

  return {
    currentVersion,
    payload,
    pushed,
    downstreamStatus,
    responseCode,
  };
}

export async function recordSubReport(
  db: D1Database,
  report: SubReportPayload,
): Promise<DownstreamClient> {
  const receivedAt = nowIso();
  const storageKey = buildSubReportKey(report.serviceUrl);
  const authTokenHash = await sha256(report.serviceUrl.trim());
  const persistedPayload: JsonObject = {
    service: report.service,
    serviceWatermark: report.serviceWatermark,
    serviceUrl: report.serviceUrl,
    databackVersion: report.databackVersion,
    ...(report.mediaStats
      ? {
          mediaStats: report.mediaStats as unknown as JsonValue,
        }
      : {}),
    reportCount: report.reportCount,
    reportedAt: report.reportedAt,
  };
  const payloadJson = stableStringify(persistedPayload);

  await db.prepare(
    `
      INSERT INTO downstream_clients (
        entry_kind,
        client_name,
        callback_url,
        client_version,
        last_sync_version,
        last_seen_at,
        last_push_at,
        last_status,
        last_response_code,
        last_error,
        service_url,
        databack_version,
        report_count,
        reported_at,
        auth_token_hash,
        auth_issued_at,
        auth_last_success_at,
        auth_failure_count,
        blacklisted_at,
        payload_json
      )
      VALUES (
        'sub-report',
        ?, ?, ?, 0, ?, NULL, 'reported', 202, NULL, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?
      )
      ON CONFLICT(callback_url) DO UPDATE SET
        entry_kind = 'sub-report',
        client_name = excluded.client_name,
        client_version = excluded.client_version,
        last_seen_at = excluded.last_seen_at,
        last_status = 'reported',
        last_response_code = 202,
        last_error = NULL,
        service_url = excluded.service_url,
        databack_version = excluded.databack_version,
        report_count = excluded.report_count,
        reported_at = excluded.reported_at,
        auth_token_hash = excluded.auth_token_hash,
        auth_issued_at = COALESCE(downstream_clients.auth_issued_at, excluded.auth_issued_at),
        auth_last_success_at = excluded.auth_last_success_at,
        auth_failure_count = 0,
        blacklisted_at = NULL,
        payload_json = excluded.payload_json
    `,
  )
    .bind(
      report.service,
      storageKey,
      Math.max(0, Number(report.databackVersion ?? 0)),
      receivedAt,
      report.serviceUrl,
      report.databackVersion,
      report.reportCount,
      report.reportedAt,
      authTokenHash,
      receivedAt,
      receivedAt,
      payloadJson,
    )
    .run();

  const storedRow = await db.prepare(
    `
      SELECT *
      FROM downstream_clients
      WHERE callback_url = ?
    `,
  )
    .bind(storageKey)
    .first<DownstreamClientRow>();

  if (!storedRow) {
    throw new Error('Failed to read back sub report record.');
  }

  return mapDownstreamClient(storedRow);
}

export async function pushSecureRecordsToRegisteredSubs(
  env: Env,
): Promise<
  Array<{
    serviceUrl: string;
    pushUrl: string;
    previousVersion: number;
    currentVersion: number;
    pushed: boolean;
    status: string;
    responseCode: number | null;
    totalRecords: number;
    lastPushAt: string | null;
    reason?: string;
  }>
> {
  const currentVersion = await getCurrentVersion(env.DB);
  const subServiceResult = await env.DB.prepare(
    `
      SELECT *
      FROM downstream_clients
      WHERE entry_kind = 'sub-report'
        AND service_url IS NOT NULL
        AND blacklisted_at IS NULL
      ORDER BY COALESCE(databack_version, 0) DESC, last_seen_at DESC
    `,
  ).all<DownstreamClientRow>();

  const rows = subServiceResult.results ?? [];
  const results: Array<{
    serviceUrl: string;
    pushUrl: string;
    previousVersion: number;
    currentVersion: number;
    pushed: boolean;
    status: string;
    responseCode: number | null;
    totalRecords: number;
    lastPushAt: string | null;
    reason?: string;
  }> = [];

  for (const row of rows) {
    const serviceUrl = row.service_url?.trim();
    if (!serviceUrl) {
      continue;
    }

    const pushUrl = buildSubPushUrl(serviceUrl);
    const previousVersion = readPushedMainVersion(row);

    if (previousVersion >= currentVersion) {
      await env.DB.prepare(
        `
          UPDATE downstream_clients
          SET last_status = 'up-to-date',
              last_response_code = 204,
              last_error = NULL
          WHERE id = ?
        `,
      )
        .bind(row.id)
        .run();

      results.push({
        serviceUrl,
        pushUrl,
        previousVersion,
        currentVersion,
        pushed: false,
        status: 'up-to-date',
        responseCode: 204,
        totalRecords: 0,
        lastPushAt: row.last_push_at,
      });
      continue;
    }

    const payload = await buildSubPushPayload(
      env.DB,
      currentVersion,
      previousVersion,
    );

    try {
      const body = JSON.stringify(payload);
      const response = await fetch(pushUrl, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${await deriveServiceAuthToken(serviceUrl)}`,
          'content-type': 'application/json',
        },
        body,
      });

      if (response.ok) {
        const pushedAt = nowIso();
        await env.DB.prepare(
          `
            UPDATE downstream_clients
            SET last_sync_version = ?,
                last_push_at = ?,
                last_status = 'pushed',
                last_response_code = ?,
                last_error = NULL
            WHERE id = ?
          `,
        )
          .bind(
            currentVersion,
            pushedAt,
            response.status,
            row.id,
          )
          .run();

        results.push({
          serviceUrl,
          pushUrl,
          previousVersion,
          currentVersion,
          pushed: true,
          status: 'pushed',
          responseCode: response.status,
          totalRecords: payload.totalRecords,
          lastPushAt: pushedAt,
        });
        continue;
      }

      const errorText = await response.text();
      await env.DB.prepare(
        `
          UPDATE downstream_clients
          SET last_status = 'push-failed',
              last_response_code = ?,
              last_error = ?
          WHERE id = ?
        `,
      )
        .bind(
          response.status,
          errorText || `Push failed with status ${response.status}.`,
          row.id,
        )
        .run();

      results.push({
        serviceUrl,
        pushUrl,
        previousVersion,
        currentVersion,
        pushed: false,
        status: 'push-failed',
        responseCode: response.status,
        totalRecords: payload.totalRecords,
        lastPushAt: row.last_push_at,
        reason: errorText || `Push failed with status ${response.status}.`,
      });
    } catch (error) {
      const reason =
        error instanceof Error
          ? error.message
          : 'Unknown push error';

      await env.DB.prepare(
        `
          UPDATE downstream_clients
          SET last_status = 'push-error',
              last_response_code = NULL,
              last_error = ?
          WHERE id = ?
        `,
      )
        .bind(reason, row.id)
        .run();

      results.push({
        serviceUrl,
        pushUrl,
        previousVersion,
        currentVersion,
        pushed: false,
        status: 'push-error',
        responseCode: null,
        totalRecords: payload.totalRecords,
        lastPushAt: row.last_push_at,
        reason,
      });
    }
  }

  return results;
}

function getSubPullMaxAttempts(env: Env): number {
  return Math.max(
    1,
    Math.min(Number(env.SUB_PULL_MAX_ATTEMPTS ?? '5'), 10),
  );
}

function getSubPullRetryDelayMs(env: Env): number {
  return Math.max(
    0,
    Number(env.SUB_PULL_RETRY_DELAY_MS ?? '60000'),
  );
}

function readRetryAfterMs(response: Response): number | null {
  const retryAfter = response.headers.get('retry-after')?.trim();
  if (!retryAfter) {
    return null;
  }

  const seconds = Number(retryAfter);
  if (Number.isFinite(seconds)) {
    return Math.max(0, seconds * 1000);
  }

  const dateMs = Date.parse(retryAfter);
  return Number.isFinite(dateMs)
    ? Math.max(0, dateMs - Date.now())
    : null;
}

async function waitMs(delayMs: number): Promise<void> {
  if (delayMs <= 0) {
    return;
  }

  await new Promise((resolve) => {
    setTimeout(resolve, delayMs);
  });
}

async function fetchSubDatabackExportWithRetry(
  env: Env,
  input: {
    serviceUrl: string;
    timeoutMs: number;
    url: string;
  },
): Promise<{
  bodyText: string;
  responseCode: number;
}> {
  const maxAttempts = getSubPullMaxAttempts(env);
  const defaultRetryDelayMs = getSubPullRetryDelayMs(env);
  let lastReason = 'Unknown pull failure';

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), input.timeoutMs);

    try {
      const response = await fetch(input.url, {
        method: 'GET',
        headers: {
          authorization: `Bearer ${await deriveServiceAuthToken(input.serviceUrl)}`,
        },
        signal: controller.signal,
      });
      const bodyText = await response.text();

      if (response.ok) {
        return {
          bodyText,
          responseCode: response.status,
        };
      }

      lastReason = bodyText || `Pull failed with status ${response.status}.`;
      if (attempt >= maxAttempts) {
        return {
          bodyText: lastReason,
          responseCode: response.status,
        };
      }

      console.warn(
        `Databack pull attempt ${attempt}/${maxAttempts} failed for ${input.serviceUrl}: ${lastReason}`,
      );
      await waitMs(readRetryAfterMs(response) ?? defaultRetryDelayMs);
    } catch (error) {
      lastReason = error instanceof Error ? error.message : 'Unknown pull error';
      if (attempt >= maxAttempts) {
        throw new Error(
          `Databack pull failed after ${maxAttempts} attempts for ${input.serviceUrl}: ${lastReason}`,
        );
      }

      console.warn(
        `Databack pull attempt ${attempt}/${maxAttempts} errored for ${input.serviceUrl}: ${lastReason}`,
      );
      await waitMs(defaultRetryDelayMs);
    } finally {
      clearTimeout(timeout);
    }
  }

  throw new Error(
    `Databack pull failed after ${maxAttempts} attempts for ${input.serviceUrl}: ${lastReason}`,
  );
}

export async function pullDatabackFromRegisteredSubs(
  env: Env,
): Promise<
  Array<{
    serviceUrl: string;
    exportUrl: string;
    previousVersion: number;
    reportedVersion: number;
    pulled: boolean;
    status: string;
    responseCode: number | null;
    receivedCount: number;
    updatedCount: number;
    skippedCount: number;
    highestPulledVersion: number;
    lastPullAt: string | null;
    reason?: string;
  }>
> {
  const batchSize = Math.max(
    1,
    Math.min(Number(env.SUB_PULL_BATCH_SIZE ?? '10'), 100),
  );
  const recordLimit = Math.max(
    1,
    Math.min(Number(env.SUB_PULL_RECORD_LIMIT ?? '100'), 500),
  );
  const timeoutMs = Math.max(
    1000,
    Number(env.SUB_PULL_TIMEOUT_MS ?? '10000'),
  );
  const subServiceResult = await env.DB.prepare(
    `
      SELECT *
      FROM downstream_clients
      WHERE entry_kind = 'sub-report'
        AND service_url IS NOT NULL
        AND blacklisted_at IS NULL
      ORDER BY COALESCE(databack_version, 0) DESC, last_seen_at DESC
      LIMIT ?
    `,
  )
    .bind(batchSize)
    .all<DownstreamClientRow>();
  const rows = subServiceResult.results ?? [];
  const results: Array<{
    serviceUrl: string;
    exportUrl: string;
    previousVersion: number;
    reportedVersion: number;
    pulled: boolean;
    status: string;
    responseCode: number | null;
    receivedCount: number;
    updatedCount: number;
    skippedCount: number;
    highestPulledVersion: number;
    lastPullAt: string | null;
    reason?: string;
  }> = [];

  for (const row of rows) {
    const serviceUrl = row.service_url?.trim();
    if (!serviceUrl) {
      continue;
    }

    const exportUrl = buildSubExportUrl(serviceUrl);
    const previousVersion = readSubPullVersion(row);
    const reportedVersion = readReportedSubVersion(row);

    if (reportedVersion <= previousVersion) {
      const checkedAt = nowIso();
      await env.DB.prepare(
        `
          UPDATE downstream_clients
          SET last_pull_at = ?,
              last_pull_status = 'up-to-date',
              last_pull_response_code = 204,
              last_pull_error = NULL
          WHERE id = ?
        `,
      )
        .bind(checkedAt, row.id)
        .run();

      results.push({
        serviceUrl,
        exportUrl,
        previousVersion,
        reportedVersion,
        pulled: false,
        status: 'up-to-date',
        responseCode: 204,
        receivedCount: 0,
        updatedCount: 0,
        skippedCount: 0,
        highestPulledVersion: previousVersion,
        lastPullAt: checkedAt,
      });
      continue;
    }

    let highestPulledVersion = previousVersion;
    let receivedCount = 0;
    let updatedCount = 0;
    let skippedCount = 0;
    let responseCode: number | null = null;
    let lastPullAt: string | null = null;
    let failed = false;

    try {
      let hasMore = true;
      let requestCount = 0;

      while (hasMore) {
        if (requestCount > 0) {
          await waitMs(getSubPullRetryDelayMs(env));
        }
        requestCount += 1;

        const requestUrl = new URL(exportUrl);
        requestUrl.searchParams.set(
          'afterVersion',
          String(highestPulledVersion),
        );
        requestUrl.searchParams.set(
          'limit',
          String(recordLimit),
        );
        const pullResponse = await fetchSubDatabackExportWithRetry(env, {
          serviceUrl,
          timeoutMs,
          url: requestUrl.toString(),
        });
        responseCode = pullResponse.responseCode;

        if (responseCode < 200 || responseCode >= 300) {
          const reason = pullResponse.bodyText
            || `Pull failed with status ${responseCode}.`;
          console.error(
            `Databack pull failed after ${getSubPullMaxAttempts(env)} attempts for ${serviceUrl}: ${reason}`,
          );
          await env.DB.prepare(
            `
              UPDATE downstream_clients
              SET last_pull_status = 'pull-failed',
                  last_pull_response_code = ?,
                  last_pull_error = ?
              WHERE id = ?
            `,
          )
            .bind(
              responseCode,
              reason,
              row.id,
            )
            .run();

          results.push({
            serviceUrl,
            exportUrl,
            previousVersion,
            reportedVersion,
            pulled: false,
            status: 'pull-failed',
            responseCode,
            receivedCount,
            updatedCount,
            skippedCount,
            highestPulledVersion,
            lastPullAt: row.last_pull_at,
            reason,
          });
          failed = true;
          hasMore = false;
          break;
        }

        const exportFile = parseSubDatabackExportFile(
          JSON.parse(pullResponse.bodyText),
        );
        const importResult = await importSubDatabackExportFile(
          env,
          serviceUrl,
          exportFile,
        );

        receivedCount += importResult.receivedCount;
        updatedCount += importResult.updatedCount;
        skippedCount += importResult.skippedCount;
        highestPulledVersion = Math.max(
          highestPulledVersion,
          importResult.highestPulledVersion,
          Number(exportFile.currentVersion ?? 0),
        );
        hasMore =
          exportFile.records.length >= recordLimit
          && highestPulledVersion < Number(exportFile.currentVersion ?? 0);
      }

      if (failed || responseCode === null) {
        continue;
      }

      lastPullAt = nowIso();
      const finalStatus =
        updatedCount > 0 || receivedCount > 0
          ? 'pulled'
          : 'up-to-date';

      await env.DB.prepare(
        `
          UPDATE downstream_clients
          SET last_pull_version = ?,
              last_pull_at = ?,
              last_pull_status = ?,
              last_pull_response_code = ?,
              last_pull_error = NULL
          WHERE id = ?
        `,
      )
        .bind(
          highestPulledVersion,
          lastPullAt,
          finalStatus,
          responseCode ?? 200,
          row.id,
        )
        .run();

      results.push({
        serviceUrl,
        exportUrl,
        previousVersion,
        reportedVersion,
        pulled: updatedCount > 0 || receivedCount > 0,
        status: finalStatus,
        responseCode,
        receivedCount,
        updatedCount,
        skippedCount,
        highestPulledVersion,
        lastPullAt,
      });
    } catch (error) {
      const reason =
        error instanceof Error
          ? error.message
          : 'Unknown pull error';

      console.error(
        `Databack pull error for ${serviceUrl}: ${reason}`,
      );
      await env.DB.prepare(
        `
          UPDATE downstream_clients
          SET last_pull_status = 'pull-error',
              last_pull_response_code = NULL,
              last_pull_error = ?
          WHERE id = ?
        `,
      )
        .bind(reason, row.id)
        .run();

      results.push({
        serviceUrl,
        exportUrl,
        previousVersion,
        reportedVersion,
        pulled: false,
        status: 'pull-error',
        responseCode: null,
        receivedCount,
        updatedCount,
        skippedCount,
        highestPulledVersion,
        lastPullAt: row.last_pull_at,
        reason,
      });
    }
  }

  return results;
}

export async function getOverview(
  db: D1Database,
): Promise<AnalyticsOverview> {
  const [totalsRow, rawBySource, syncStatuses, versionHistory] =
    await Promise.all([
      db
        .prepare(
          `
            SELECT
              (SELECT COUNT(*) FROM raw_records) AS rawRecords,
              (SELECT COUNT(*) FROM secure_records) AS secureRecords,
              (SELECT COUNT(*) FROM downstream_clients) AS downstreamClients,
              (SELECT COALESCE(MAX(version), 0) FROM secure_records) AS currentVersion
          `,
        )
        .first<{
          rawRecords: number;
          secureRecords: number;
          downstreamClients: number;
          currentVersion: number;
        }>(),
      db
        .prepare(
          `
            SELECT source, COUNT(*) AS count
            FROM raw_records
            GROUP BY source
            ORDER BY count DESC, source ASC
          `,
        )
        .all<{ source: string; count: number }>(),
      db
        .prepare(
          `
            SELECT last_status AS status, COUNT(*) AS count
            FROM downstream_clients
            GROUP BY last_status
            ORDER BY count DESC, status ASC
          `,
        )
        .all<{ status: string; count: number }>(),
      db
        .prepare(
          `
            SELECT record_key AS recordKey, version
            FROM secure_records
            ORDER BY version DESC
            LIMIT 20
          `,
        )
        .all<{ recordKey: string; version: number }>(),
    ]);

  return {
    totals: {
      rawRecords: Number(totalsRow?.rawRecords ?? 0),
      secureRecords: Number(totalsRow?.secureRecords ?? 0),
      downstreamClients: Number(totalsRow?.downstreamClients ?? 0),
      currentVersion: Number(totalsRow?.currentVersion ?? 0),
    },
    rawBySource: rawBySource.results ?? [],
    syncStatuses: syncStatuses.results ?? [],
    versionHistory: versionHistory.results ?? [],
  };
}

export async function listSchoolMediaRecords(
  db: D1Database,
  options: {
    includeR18?: boolean;
    limit?: number;
    publicOnly?: boolean;
    schoolNameNorm?: string;
    status?: SchoolMediaStatus;
    tagSlug?: string;
  } = {},
): Promise<SchoolMediaRecord[]> {
  const where: string[] = [];
  const params: Array<number | string> = [];
  const tagSlug = options.tagSlug?.trim()
    ? normalizeTagSlug(options.tagSlug)
    : '';

  if (options.publicOnly) {
    where.push("status = 'approved'");
  } else if (options.status) {
    where.push('status = ?');
    params.push(options.status);
  }
  if (!options.includeR18 && tagSlug !== R18_TAG_SLUG) {
    where.push(`
      NOT EXISTS (
        SELECT 1
        FROM school_media_tags AS r18_links
        INNER JOIN media_tags AS r18_tags
          ON r18_tags.id = r18_links.tag_id
        WHERE r18_links.media_id = school_media.id
          AND r18_tags.slug = ?
      )
    `);
    params.push(R18_TAG_SLUG);
  }
  if (options.schoolNameNorm?.trim()) {
    where.push('school_name_norm = ?');
    params.push(options.schoolNameNorm.trim());
  }
  if (tagSlug) {
    where.push(`
      EXISTS (
        SELECT 1
        FROM school_media_tags AS filter_links
        INNER JOIN media_tags AS filter_tags
          ON filter_tags.id = filter_links.tag_id
        WHERE filter_links.media_id = school_media.id
          AND filter_tags.slug = ?
      )
    `);
    params.push(tagSlug);
  }

  const sql = `
    SELECT *
    FROM school_media
    ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
    ORDER BY updated_at DESC
    LIMIT ?
  `;
  const result = await db.prepare(sql)
    .bind(...params, Math.max(1, Math.min(options.limit ?? 200, 500)))
    .all<SchoolMediaRow>();
  const records = [];

  for (const row of result.results ?? []) {
    records.push(await mapSchoolMediaRecord(db, row));
  }

  return records;
}

export async function reviewSchoolMediaRecord(
  db: D1Database,
  input: {
    id: string;
    note?: string;
    status: Extract<SchoolMediaStatus, 'approved' | 'rejected'>;
  },
): Promise<SchoolMediaRecord> {
  const reviewedAt = nowIso();
  await db.prepare(
    `
      UPDATE school_media
      SET status = ?,
          review_note = ?,
          reviewed_at = ?,
          updated_at = ?
      WHERE id = ?
    `,
  )
    .bind(
      input.status,
      input.note?.trim() || null,
      reviewedAt,
      reviewedAt,
      input.id,
    )
    .run();

  const row = await db.prepare(
    `
      SELECT *
      FROM school_media
      WHERE id = ?
      LIMIT 1
    `,
  )
    .bind(input.id)
    .first<SchoolMediaRow>();
  if (!row) {
    throw new Error('Media record was not found.');
  }

  return mapSchoolMediaRecord(db, row);
}

export async function getSchoolMediaOverview(
  db: D1Database,
): Promise<SchoolMediaOverview> {
  const [statsRow, schools, topTags] = await Promise.all([
    db.prepare(
      `
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN status = 'pending_review' THEN 1 ELSE 0 END) AS pendingReview,
          SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved,
          SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected,
          SUM(CASE WHEN is_r18 = 1 THEN 1 ELSE 0 END) AS r18,
          COUNT(DISTINCT school_name_norm) AS schools
        FROM school_media
      `,
    ).first<SchoolMediaStats>(),
    db.prepare(
      `
        SELECT
          school_name AS schoolName,
          school_name_norm AS schoolNameNorm,
          COUNT(*) AS total,
          SUM(CASE WHEN status = 'pending_review' THEN 1 ELSE 0 END) AS pendingReview,
          SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved,
          SUM(CASE WHEN is_r18 = 1 THEN 1 ELSE 0 END) AS r18
        FROM school_media
        GROUP BY school_name_norm
        ORDER BY total DESC, school_name ASC
        LIMIT 20
      `,
    ).all<{
      approved: number;
      pendingReview: number;
      r18: number;
      schoolName: string;
      schoolNameNorm: string;
      total: number;
    }>(),
    db.prepare(
      `
        SELECT
          tags.label,
          tags.slug,
          COUNT(*) AS count
        FROM media_tags AS tags
        INNER JOIN school_media_tags AS links
          ON links.tag_id = tags.id
        INNER JOIN school_media AS media
          ON media.id = links.media_id
        GROUP BY tags.slug
        ORDER BY count DESC, tags.label ASC
        LIMIT 20
      `,
    ).all<{
      count: number;
      label: string;
      slug: string;
    }>(),
  ]);

  return {
    stats: {
      approved: Number(statsRow?.approved ?? 0),
      pendingReview: Number(statsRow?.pendingReview ?? 0),
      rejected: Number(statsRow?.rejected ?? 0),
      r18: Number(statsRow?.r18 ?? 0),
      schools: Number(statsRow?.schools ?? 0),
      total: Number(statsRow?.total ?? 0),
    },
    schools: (schools.results ?? []).map((row) => ({
      approved: Number(row.approved ?? 0),
      pendingReview: Number(row.pendingReview ?? 0),
      r18: Number(row.r18 ?? 0),
      schoolName: row.schoolName,
      schoolNameNorm: row.schoolNameNorm,
      total: Number(row.total ?? 0),
    })),
    topTags: (topTags.results ?? []).map((row) => ({
      count: Number(row.count ?? 0),
      label: row.label,
      slug: row.slug,
    })),
  };
}

export async function getPublicDataset(
  db: D1Database,
): Promise<PublicDatasetResponse> {
  const [rawRecords, versionRow] = await Promise.all([
    listRawRecords(db),
    db
      .prepare(
        'SELECT COALESCE(MAX(version), 0) AS version FROM secure_records',
      )
      .first<{ version: number | null }>(),
  ]);

  const provinceCounts = new Map<string, number>();
  let ageTotal = 0;
  let ageCount = 0;

  const data = rawRecords.map((record) => {
    const province = readStringField(record.payload, 'province').trim();
    if (province) {
      provinceCounts.set(
        province,
        (provinceCounts.get(province) ?? 0) + 1,
      );
    }

    const age = readNumberField(record.payload, 'age');
    if (age !== null) {
      ageTotal += age;
      ageCount += 1;
    }

    return mapPublicDatasetItem(record);
  });

  return {
    avg_age: ageCount ? Math.round(ageTotal / ageCount) : 0,
    last_synced: Number(versionRow?.version ?? 0),
    statistics: Array.from(provinceCounts.entries())
      .map(([province, count]) => ({
        province,
        count,
      }))
      .sort((left, right) => {
        if (right.count !== left.count) {
          return right.count - left.count;
        }

        return left.province.localeCompare(right.province, 'zh-CN');
      }),
    data,
  };
}

export async function getAdminSnapshot(
  db: D1Database,
  limits: {
    mediaRecords?: number;
    rawRecords?: number;
    secureRecords?: number;
    downstreamClients?: number;
  } = {
    mediaRecords: 200,
    rawRecords: 200,
    secureRecords: 200,
    downstreamClients: 200,
  },
): Promise<AdminSnapshot> {
  const [overview, mediaOverview, mediaRecords, rawRecords, secureRecords, downstreamClients] =
    await Promise.all([
      getOverview(db),
      getSchoolMediaOverview(db),
      listSchoolMediaRecords(db, {
        includeR18: true,
        limit: limits.mediaRecords,
      }),
      listRawRecords(db, limits.rawRecords),
      listSecureRecords(db, limits.secureRecords),
      listDownstreamClients(db, limits.downstreamClients),
    ]);

  return {
    mediaOverview,
    mediaRecords,
    overview,
    rawRecords,
    secureRecords,
    downstreamClients,
  };
}
