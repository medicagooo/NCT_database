import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Context } from 'hono';
import { z } from 'zod';
import { toJsonObject } from './lib/json';
import {
  ingestSubFormRecords,
  NCT_SUB_SERVICE_WATERMARK,
  getAdminSnapshot,
  getSubReportThrottleState,
  getPublicDataset,
  getPublishedPayload,
  ingestRecords,
  ingestSubMediaRecords,
  isRecognizedSubService,
  listSchoolMediaRecords,
  pullDatabackFromRegisteredSubs,
  pushSecureRecordsToRegisteredSubs,
  rebuildSecureRecords,
  recordSubReport,
  reviewSchoolMediaRecord,
  verifySubServiceToken,
} from './lib/data';
import { exportSnapshot, hasExportBucket } from './lib/export';
import {
  checkMediaBucketCapacity,
  hasMediaBucket,
  isSafeLocalMediaObjectKey,
  storeSubMediaObject,
} from './lib/media-storage';
import {
  AdminAuthError,
  assertAdminAuth,
  deleteAdminSession,
  getAdminAuthStatus,
  loginAdminPassword,
  setupAdminPassword,
} from './lib/adminAuth';
import { parseTabularImport } from './lib/tabular-import';
import { readBearerToken } from './lib/service-auth';

const ingestSchema = z.object({
  records: z
    .array(
      z.object({
        dataSourceType: z.enum(['questionnaire', 'batch_query']).optional(),
        recordKey: z.string().optional(),
        source: z.string().optional(),
        encryptFields: z.array(z.string()).optional(),
        payload: z
          .record(z.string(), z.unknown())
          .transform((value) => toJsonObject(value)),
      }),
    )
    .min(1),
});

const subReportSchema = z.object({
  service: z.string().min(1),
  serviceWatermark: z.literal(NCT_SUB_SERVICE_WATERMARK),
  serviceUrl: z.string().url(),
  databackVersion: z.number().int().min(0).nullable(),
  mediaStats: z.object({
    approved: z.number().int().min(0),
    pendingReview: z.number().int().min(0),
    rejected: z.number().int().min(0),
    r18: z.number().int().min(0),
    schools: z.number().int().min(0),
    total: z.number().int().min(0),
  }).optional(),
  reportCount: z.number().int().min(1),
  reportedAt: z.string().min(1),
});

const subFormRecordsSchema = z.object({
  serviceUrl: z.string().url(),
  records: z
    .array(
      z.object({
        databackFingerprint: z.string().min(1),
        databackVersion: z.number().int().min(0),
        payload: z
          .record(z.string(), z.unknown())
          .transform((value) => toJsonObject(value)),
        recordKey: z.string().min(1),
        updatedAt: z.string().min(1),
      }),
    )
    .min(1),
});

const subMediaRecordsSchema = z.object({
  serviceUrl: z.string().url(),
  records: z
    .array(
      z.object({
        byteSize: z.number().int().min(1),
        city: z.string(),
        contentType: z.string().min(1),
        county: z.string(),
        fileName: z.string().min(1),
        id: z.string().min(1),
        isR18: z.boolean().optional(),
        mediaType: z.enum(['image', 'video']),
        objectKey: z.string().min(1),
        province: z.string(),
        publicUrl: z.string().url(),
        schoolAddress: z.string(),
        schoolName: z.string().min(1),
        schoolNameNorm: z.string().min(1),
        tags: z.array(
          z.object({
            label: z.string().min(1),
            slug: z.string().min(1),
            isSystem: z.boolean(),
          }),
        ),
        updatedAt: z.string().min(1),
        uploadedAt: z.string().nullable(),
      }),
    )
    .min(1),
});

const subMediaObjectSchema = z.object({
  byteSize: z.coerce.number().int().min(1),
  contentType: z.string().min(1),
  mediaId: z.string().min(1),
  objectKey: z.string().min(1),
  serviceUrl: z.string().url(),
});

const mediaReviewSchema = z.object({
  note: z.string().max(1000).optional(),
  status: z.enum(['approved', 'rejected']),
});

type ParsedSubReport = {
  databackVersion: number | null;
  mediaStats?: {
    approved: number;
    pendingReview: number;
    rejected: number;
    r18: number;
    schools: number;
    total: number;
  };
  reportCount: number;
  reportedAt: string;
  service: string;
  serviceUrl: string;
  serviceWatermark: typeof NCT_SUB_SERVICE_WATERMARK;
};

type ParsedSubFormRecords = {
  records: Array<{
    databackFingerprint: string;
    databackVersion: number;
    recordKey: string;
  }>;
  serviceUrl: string;
};

function fakeIdFromServiceUrl(serviceUrl: string): number {
  let hash = 2166136261;
  for (const char of serviceUrl) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }

  return Math.abs(hash % 900000) + 100000;
}

function buildFakeSubStored(report: ParsedSubReport) {
  const now = new Date().toISOString();

  return {
    authFailureCount: 0,
    authIssuedAt: now,
    authLastFailureAt: null,
    authLastSuccessAt: now,
    blacklistedAt: null,
    callbackUrl: report.serviceUrl,
    clientName: report.service,
    clientVersion: Math.max(0, Number(report.databackVersion ?? 0)),
    databackVersion: report.databackVersion,
    entryKind: 'sub-report',
    id: fakeIdFromServiceUrl(report.serviceUrl),
    lastError: null,
    lastPullAt: null,
    lastPullError: null,
    lastPullResponseCode: null,
    lastPullStatus: null,
    lastPullVersion: Math.max(0, Number(report.databackVersion ?? 0)),
    lastPushAt: now,
    lastResponseCode: 202,
    lastSeenAt: now,
    lastStatus: 'reported',
    lastSyncVersion: Math.max(0, Number(report.databackVersion ?? 0)),
    payload: {
      databackVersion: report.databackVersion,
      mediaStats: report.mediaStats,
      reportCount: report.reportCount,
      reportedAt: report.reportedAt,
      service: report.service,
      serviceUrl: report.serviceUrl,
      serviceWatermark: report.serviceWatermark,
    },
    reportCount: report.reportCount,
    reportedAt: report.reportedAt,
    serviceUrl: report.serviceUrl,
  };
}

function buildFakeFormResults(request: ParsedSubFormRecords) {
  return request.records.slice(0, 1).map((record) => ({
    databackFingerprint: `accepted:${crypto.randomUUID()}`,
    motherVersion: Math.max(0, Number(record.databackVersion)),
    recordKey: `accepted:${crypto.randomUUID()}`,
    updated: true,
  }));
}

function buildFakeMediaResults(request: {
  records: Array<{
    id: string;
  }>;
}) {
  return request.records.slice(0, 1).map((record) => ({
    mediaId: record.id,
    updated: true,
  }));
}

function buildFakeMediaObjectResult() {
  return {
    accepted: true,
    stored: false,
  };
}

const tabularImportSchema = z.object({
  dataSourceType: z.enum(['questionnaire', 'batch_query']).optional(),
  dryRun: z.boolean().optional(),
  source: z.string().max(120).optional(),
  text: z.string().min(1),
});

const EXPORT_CRON = '0 18 * * *';
const MEDIA_CAPACITY_ALERT_CRON = '0 * * * *';

const app = new Hono<{ Bindings: Env }>();
const publicCors = cors({
  origin: '*',
  allowHeaders: [
    'content-type',
    'authorization',
    'x-api-token',
  ],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
});

function adminAuthErrorResponse(context: Context, error: unknown): Response {
  if (error instanceof AdminAuthError) {
    return context.json(
      {
        code: error.code,
        error: error.message,
      },
      error.status as 400 | 401 | 409,
    );
  }

  throw error;
}

async function assertIngestAuth(
  context: Context<{ Bindings: Env }>,
): Promise<Response | null> {
  // External ingest tokens are intentionally disabled; raw writes are limited to the admin console session.
  return assertAdminAuth(context);
}

function getSubAuthMaxFailures(env: Env): number {
  return Math.max(
    1,
    Number(env.SUB_AUTH_MAX_FAILURES ?? '5'),
  );
}

async function serveConsoleShell(context: {
  env: Env;
  req: {
    url: string;
  };
}) {
  // `/Console` is a client-side app, while `/` stays reserved for the public JSON dataset.
  const response = await context.env.ASSETS.fetch(
    new Request(new URL('/index.html', context.req.url)),
  );

  if (response.status !== 404) {
    return response;
  }

  return new Response(
    'Console assets not found. Build the client before deploying the Worker.',
    {
      status: 404,
      headers: {
        'content-type': 'text/plain; charset=utf-8',
      },
    },
  );
}

app.use('/', publicCors);
app.use('/api/*', publicCors);

app.get('/', async (context) => {
  return context.json(await getPublicDataset(context.env.DB));
});

app.get('/Console', async (context) => {
  return serveConsoleShell(context);
});

app.get('/Console/*', async (context) => {
  return serveConsoleShell(context);
});

app.get('/console', async (context) => {
  return serveConsoleShell(context);
});

app.get('/console/*', async (context) => {
  return serveConsoleShell(context);
});

app.get('/assets/*', async (context) => {
  return context.env.ASSETS.fetch(context.req.raw);
});

app.get('/api/health', async (context) => {
  const snapshot = await getAdminSnapshot(context.env.DB);

  return context.json({
    status: 'ok',
    app: context.env.APP_NAME ?? 'NCT API SQL',
    currentVersion: snapshot.overview.totals.currentVersion,
    checkedAt: new Date().toISOString(),
  });
});

app.post('/api/ingest', async (context) => {
  const authError = await assertIngestAuth(context);
  if (authError) {
    return authError;
  }

  const payload = await context.req.json();
  const parsed = ingestSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(
      {
        error: 'Invalid ingest payload.',
        details: parsed.error.flatten(),
      },
      400,
    );
  }

  const results = await ingestRecords(context.env, parsed.data.records);
  if (results.some((item) => item.updated)) {
    context.executionCtx?.waitUntil(pushSecureRecordsToRegisteredSubs(context.env));
  }

  return context.json({
    message: 'Records ingested successfully.',
    updatedCount: results.filter((item) => item.updated).length,
    results,
  });
});

app.post('/api/sync', async (context) => {
  return context.json(
    {
      error:
        'Deprecated. Mother now pushes published secure records to registered sub services, and subs report their own status separately.',
    },
    410,
  );
});

app.post('/api/sub/report', async (context): Promise<Response> => {
  const payload = await context.req.json();
  const parsed = subReportSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(
      {
        error: 'Invalid sub report payload.',
        details: parsed.error.flatten(),
      },
      400,
    );
  }

  if (!isRecognizedSubService(
    parsed.data.service,
    parsed.data.serviceWatermark,
  )) {
    return context.json(
      {
        error: 'Only nct-api-sql-sub reports are accepted.',
      },
      403,
    );
  }

  const tokenVerification = await verifySubServiceToken(
    context.env,
    parsed.data.serviceUrl,
    readBearerToken(context.req.raw),
    getSubAuthMaxFailures(context.env),
    {
      allowUnregistered: true,
    },
  );
  if (!tokenVerification.ok) {
    return context.json(
      {
        accepted: true,
        stored: buildFakeSubStored(parsed.data),
      },
      202,
    );
  }
  const verifiedServiceUrl = tokenVerification.stored?.serviceUrl?.trim()
    || parsed.data.serviceUrl;

  const throttleState = await getSubReportThrottleState(
    context.env.DB,
    verifiedServiceUrl,
    Math.max(0, Number(context.env.SUB_REPORT_MIN_INTERVAL_MS ?? '5000')),
  );
  if (throttleState) {
    return context.json(
      {
        error: 'Sub report was throttled.',
        retryAfterMs: throttleState.retryAfterMs,
        lastSeenAt: throttleState.lastSeenAt,
      },
      429,
    );
  }

  const stored = await recordSubReport(context.env.DB, {
    ...parsed.data,
    serviceUrl: verifiedServiceUrl,
  });
  context.executionCtx?.waitUntil(pushSecureRecordsToRegisteredSubs(context.env));

  return context.json(
    {
      accepted: true,
      stored,
    },
    202,
  );
});

app.post('/api/sub/form-records', async (context): Promise<Response> => {
  const payload = await context.req.json();
  const parsed = subFormRecordsSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(
      {
        error: 'Invalid sub form sync payload.',
        details: parsed.error.flatten(),
      },
      400,
    );
  }

  const tokenVerification = await verifySubServiceToken(
    context.env,
    parsed.data.serviceUrl,
    readBearerToken(context.req.raw),
    getSubAuthMaxFailures(context.env),
  );
  if (!tokenVerification.ok) {
    return context.json(
      {
        accepted: true,
        results: buildFakeFormResults(parsed.data),
      },
      202,
    );
  }
  const verifiedServiceUrl = tokenVerification.stored?.serviceUrl?.trim()
    || parsed.data.serviceUrl;

  const results = await ingestSubFormRecords(context.env, {
    ...parsed.data,
    serviceUrl: verifiedServiceUrl,
  });
  if (results.some((item) => item.updated)) {
    context.executionCtx?.waitUntil(pushSecureRecordsToRegisteredSubs(context.env));
  }
  return context.json(
    {
      accepted: true,
      results,
    },
    202,
  );
});

app.post('/api/sub/media-records', async (context): Promise<Response> => {
  const payload = await context.req.json();
  const parsed = subMediaRecordsSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(
      {
        error: 'Invalid sub media sync payload.',
        details: parsed.error.flatten(),
      },
      400,
    );
  }

  const tokenVerification = await verifySubServiceToken(
    context.env,
    parsed.data.serviceUrl,
    readBearerToken(context.req.raw),
    getSubAuthMaxFailures(context.env),
  );
  if (!tokenVerification.ok) {
    return context.json(
      {
        accepted: true,
        results: buildFakeMediaResults(parsed.data),
      },
      202,
    );
  }

  const verifiedServiceUrl = tokenVerification.stored?.serviceUrl?.trim()
    || parsed.data.serviceUrl;
  const results = await ingestSubMediaRecords(context.env, {
    ...parsed.data,
    serviceUrl: verifiedServiceUrl,
  });

  return context.json(
    {
      accepted: true,
      results,
    },
    202,
  );
});

app.post('/api/sub/media-objects', async (context): Promise<Response> => {
  if (!hasMediaBucket(context.env)) {
    return context.json(
      {
        error: 'R2 media bucket is not configured.',
      },
      503,
    );
  }

  const url = new URL(context.req.url);
  const parsed = subMediaObjectSchema.safeParse({
    byteSize: url.searchParams.get('byteSize'),
    contentType: url.searchParams.get('contentType') || context.req.header('content-type') || '',
    mediaId: url.searchParams.get('mediaId'),
    objectKey: url.searchParams.get('objectKey'),
    serviceUrl: url.searchParams.get('serviceUrl'),
  });
  if (!parsed.success) {
    return context.json(
      {
        error: 'Invalid sub media object sync payload.',
        details: parsed.error.flatten(),
      },
      400,
    );
  }

  const tokenVerification = await verifySubServiceToken(
    context.env,
    parsed.data.serviceUrl,
    readBearerToken(context.req.raw),
    getSubAuthMaxFailures(context.env),
  );
  if (!tokenVerification.ok) {
    return context.json(buildFakeMediaObjectResult(), 202);
  }

  if (!context.req.raw.body) {
    return context.json(
      {
        error: 'Media object body is required.',
      },
      400,
    );
  }

  const verifiedServiceUrl = tokenVerification.stored?.serviceUrl?.trim()
    || parsed.data.serviceUrl;
  const result = await storeSubMediaObject(context.env, {
    body: context.req.raw.body,
    byteSize: parsed.data.byteSize,
    contentType: parsed.data.contentType,
    mediaId: parsed.data.mediaId,
    objectKey: parsed.data.objectKey,
    requestUrl: context.req.url,
    serviceUrl: verifiedServiceUrl,
  });

  return context.json(
    {
      accepted: true,
      mediaId: parsed.data.mediaId,
      ...result,
    },
    result.stored ? 202 : 409,
  );
});

app.get('/api/media/files/*', async (context) => {
  if (!hasMediaBucket(context.env)) {
    return context.json(
      {
        error: 'R2 media bucket is not configured.',
      },
      503,
    );
  }

  const prefix = '/api/media/files/';
  const pathname = new URL(context.req.raw.url).pathname;
  const encodedObjectKey = pathname.startsWith(prefix)
    ? pathname.slice(prefix.length)
    : '';
  let objectKey = '';
  try {
    objectKey = decodeURIComponent(encodedObjectKey);
  } catch {
    objectKey = '';
  }
  if (!objectKey || !isSafeLocalMediaObjectKey(objectKey)) {
    return context.json(
      {
        error: 'Media file key is invalid.',
      },
      400,
    );
  }

  const object = await context.env.MEDIA_BUCKET.get(objectKey);
  if (!object) {
    return context.json(
      {
        error: 'Media file was not found.',
      },
      404,
    );
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('cache-control', headers.get('cache-control') ?? 'public, max-age=31536000, immutable');
  headers.set('content-type', headers.get('content-type') ?? 'application/octet-stream');
  headers.set('etag', object.httpEtag);

  return new Response(object.body, {
    headers,
  });
});

app.get('/api/public/secure-records', async (context) => {
  const currentVersion = Number(
    context.req.query('currentVersion') ?? '0',
  );
  const mode = context.req.query('mode') === 'delta' ? 'delta' : 'full';

  const payload = await getPublishedPayload(
    context.env.DB,
    await context.env.DB.prepare(
      'SELECT COALESCE(MAX(version), 0) AS version FROM secure_records',
    ).first<{ version: number }>().then((row) => Number(row?.version ?? 0)),
    currentVersion,
    mode,
  );

  return context.json(payload);
});

app.get('/api/public/media', async (context) => {
  const tagSlug = context.req.query('tagSlug')?.trim() || context.req.query('tag')?.trim();
  const includeR18 = context.req.query('includeR18') === 'true';
  const schoolNameNorm = context.req.query('schoolNameNorm')?.trim();
  const limit = Math.max(
    1,
    Math.min(Number(context.req.query('limit') ?? '100'), 200),
  );

  return context.json({
    media: await listSchoolMediaRecords(context.env.DB, {
      includeR18,
      limit,
      publicOnly: true,
      schoolNameNorm,
      tagSlug,
    }),
  });
});

app.get('/api/admin/auth/status', async (context) => {
  return context.json(await getAdminAuthStatus(context.env.DB));
});

app.post('/api/admin/auth/setup', async (context) => {
  try {
    const body = await context.req.json() as {
      password?: unknown;
    };

    return context.json({
      configured: true,
      ...await setupAdminPassword(context.env.DB, body.password),
    });
  } catch (error) {
    return adminAuthErrorResponse(context, error);
  }
});

app.post('/api/admin/auth/login', async (context) => {
  try {
    const body = await context.req.json() as {
      password?: unknown;
    };

    return context.json({
      configured: true,
      ...await loginAdminPassword(context.env.DB, body.password),
    });
  } catch (error) {
    return adminAuthErrorResponse(context, error);
  }
});

app.post('/api/admin/auth/logout', async (context) => {
  await deleteAdminSession(context.env.DB, context.req.raw);
  return context.body(null, 204);
});

app.get('/api/admin/snapshot', async (context) => {
  const authError = await assertAdminAuth(context);
  if (authError) {
    return authError;
  }

  return context.json(await getAdminSnapshot(context.env.DB));
});

app.post('/api/admin/media/:id/review', async (context) => {
  const authError = await assertAdminAuth(context);
  if (authError) {
    return authError;
  }

  const payload = await context.req.json();
  const parsed = mediaReviewSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(
      {
        error: 'Invalid media review payload.',
        details: parsed.error.flatten(),
      },
      400,
    );
  }

  return context.json({
    media: await reviewSchoolMediaRecord(context.env.DB, {
      id: context.req.param('id'),
      note: parsed.data.note,
      status: parsed.data.status,
    }),
  });
});

app.post('/api/admin/rebuild-secure', async (context) => {
  const authError = await assertAdminAuth(context);
  if (authError) {
    return authError;
  }

  const results = await rebuildSecureRecords(context.env);
  if (results.some((item) => item.updated)) {
    context.executionCtx?.waitUntil(pushSecureRecordsToRegisteredSubs(context.env));
  }

  return context.json({
    message: 'Secure table rebuilt from raw records.',
    processed: results.length,
    updated: results.filter((item) => item.updated).length,
    results,
  });
});

app.post('/api/admin/import-table', async (context) => {
  const authError = await assertAdminAuth(context);
  if (authError) {
    return authError;
  }

  const payload = await context.req.json();
  const parsed = tabularImportSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(
      {
        error: 'Invalid import payload.',
        details: parsed.error.flatten(),
      },
      400,
    );
  }

  const importPlan = await parseTabularImport(parsed.data.text, {
    dataSourceType: parsed.data.dataSourceType,
    source: parsed.data.source,
  });

  if (parsed.data.dryRun) {
    return context.json({
      dryRun: true,
      duplicateRowCount: importPlan.duplicateRowCount,
      inputRowCount: importPlan.inputRowCount,
      importedCount: 0,
      parsedRowCount: importPlan.parsedRowCount,
      previewRecords: importPlan.previewRecords,
      recognizedColumns: importPlan.recognizedColumns,
      results: [],
      skippedEmptyRowCount: importPlan.skippedEmptyRowCount,
      unknownColumns: importPlan.unknownColumns,
      updatedCount: 0,
    });
  }

  if (importPlan.records.length === 0) {
    return context.json(
      {
        error: 'No importable rows were found.',
        duplicateRowCount: importPlan.duplicateRowCount,
        inputRowCount: importPlan.inputRowCount,
        parsedRowCount: importPlan.parsedRowCount,
        previewRecords: importPlan.previewRecords,
        recognizedColumns: importPlan.recognizedColumns,
        skippedEmptyRowCount: importPlan.skippedEmptyRowCount,
        unknownColumns: importPlan.unknownColumns,
      },
      400,
    );
  }

  const results = await ingestRecords(context.env, importPlan.records);
  if (results.some((item) => item.updated)) {
    context.executionCtx?.waitUntil(pushSecureRecordsToRegisteredSubs(context.env));
  }

  return context.json({
    dryRun: false,
    duplicateRowCount: importPlan.duplicateRowCount,
    inputRowCount: importPlan.inputRowCount,
    importedCount: results.length,
    message: 'Tabular import completed.',
    parsedRowCount: importPlan.parsedRowCount,
    previewRecords: importPlan.previewRecords,
    recognizedColumns: importPlan.recognizedColumns,
    results,
    skippedEmptyRowCount: importPlan.skippedEmptyRowCount,
    unknownColumns: importPlan.unknownColumns,
    updatedCount: results.filter((item) => item.updated).length,
  });
});

app.post('/api/admin/export-now', async (context) => {
  const authError = await assertAdminAuth(context);
  if (authError) {
    return authError;
  }

  if (!hasExportBucket(context.env)) {
    return context.json(
      {
        error: 'R2 export bucket is not configured.',
      },
      503,
    );
  }

  const result = await exportSnapshot(context.env);
  return context.json({
    message: 'Export completed.',
    ...result,
  });
});

app.post('/api/admin/media-capacity-check', async (context) => {
  const authError = await assertAdminAuth(context);
  if (authError) {
    return authError;
  }

  if (!hasMediaBucket(context.env)) {
    return context.json(
      {
        error: 'R2 media bucket is not configured.',
      },
      503,
    );
  }

  return context.json({
    message: 'Media capacity check completed.',
    ...await checkMediaBucketCapacity(context.env),
  });
});

app.post('/api/admin/push-now', async (context) => {
  const authError = await assertAdminAuth(context);
  if (authError) {
    return authError;
  }

  const results = await pushSecureRecordsToRegisteredSubs(context.env);
  return context.json({
    message: 'Push run completed.',
    pushedTargets: results.filter((item) => item.pushed).length,
    totalTargets: results.length,
    results,
  });
});

app.post('/api/admin/pull-now', async (context) => {
  const authError = await assertAdminAuth(context);
  if (authError) {
    return authError;
  }

  const results = await pullDatabackFromRegisteredSubs(context.env);
  if (results.some((item) => item.pulled)) {
    context.executionCtx?.waitUntil(pushSecureRecordsToRegisteredSubs(context.env));
  }
  return context.json({
    message: 'Recovery pull run completed.',
    totalTargets: results.length,
    pulledTargets: results.filter((item) => item.pulled).length,
    results,
  });
});

app.notFound(async (context) => {
  if (context.req.path.startsWith('/api/')) {
    return context.json(
      {
        error: 'Not found.',
      },
      404,
    );
  }

  const assetResponse = await context.env.ASSETS.fetch(context.req.raw);
  if (assetResponse.status !== 404) {
    return assetResponse;
  }

  return context.json(
    {
      error: 'Not found.',
    },
    404,
  );
});

export default {
  fetch(request: Request, env: Env, executionCtx: ExecutionContext) {
    return app.fetch(request, env, executionCtx);
  },
  scheduled(
    controller: ScheduledController,
    env: Env,
    executionCtx: ExecutionContext,
  ) {
    if (controller.cron === EXPORT_CRON && hasExportBucket(env)) {
      executionCtx.waitUntil(exportSnapshot(env));
    }
    if (controller.cron === MEDIA_CAPACITY_ALERT_CRON && hasMediaBucket(env)) {
      executionCtx.waitUntil(checkMediaBucketCapacity(env));
    }
  },
};
