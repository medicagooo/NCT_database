import { sha256 } from './crypto';

const DEFAULT_CAPACITY_ALERT_BYTES = 8_000_000_000;
const DEFAULT_CAPACITY_ALERT_MIN_INTERVAL_MS = 24 * 60 * 60 * 1000;
const CAPACITY_ALERT_STATE_KEY = 'media_bucket_capacity_alert';

type MediaObjectBody = Parameters<R2Bucket['put']>[1];

type CapacityAlertState = {
  lastAlertAt?: string;
};

export function hasMediaBucket(env: Env): env is Env & { MEDIA_BUCKET: R2Bucket } {
  return Boolean(env.MEDIA_BUCKET);
}

function nowIso(): string {
  return new Date().toISOString();
}

function readPositiveNumber(value: unknown, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function encodePathSegment(segment: string): string {
  return encodeURIComponent(segment).replaceAll('%2F', '/');
}

export function encodeObjectKeyPath(objectKey: string): string {
  return objectKey
    .split('/')
    .map((segment) => encodePathSegment(segment))
    .join('/');
}

export function isSafeMediaObjectKey(objectKey: string): boolean {
  return objectKey.startsWith('media/')
    && !objectKey.startsWith('/')
    && !objectKey.includes('\\')
    && objectKey.split('/').every((segment) => segment && segment !== '..');
}

export function isSafeLocalMediaObjectKey(objectKey: string): boolean {
  return objectKey.startsWith('sub-media/')
    && !objectKey.startsWith('/')
    && !objectKey.includes('\\')
    && objectKey.split('/').every((segment) => segment && segment !== '..');
}

async function buildLocalMediaObjectKey(
  serviceUrl: string,
  sourceObjectKey: string,
): Promise<string> {
  const sourceHash = (await sha256(serviceUrl.trim())).slice(0, 24);
  return `sub-media/${sourceHash}/${sourceObjectKey}`;
}

function buildLocalMediaPublicUrl(requestUrl: string, localObjectKey: string): string {
  return new URL(`/api/media/files/${encodeObjectKeyPath(localObjectKey)}`, requestUrl).toString();
}

export async function storeSubMediaObject(
  env: Env,
  input: {
    body: MediaObjectBody;
    byteSize: number;
    contentType: string;
    mediaId: string;
    objectKey: string;
    requestUrl: string;
    serviceUrl: string;
  },
): Promise<{
  localObjectKey?: string;
  publicUrl?: string;
  reason?: string;
  stored: boolean;
}> {
  if (!hasMediaBucket(env)) {
    throw new Error('MEDIA_BUCKET is not configured.');
  }
  if (!isSafeMediaObjectKey(input.objectKey)) {
    return {
      reason: 'Media object key is invalid.',
      stored: false,
    };
  }

  const existing = await env.DB.prepare(
    `
      SELECT id
      FROM school_media
      WHERE source_service_url = ?
        AND source_media_id = ?
      LIMIT 1
    `,
  )
    .bind(input.serviceUrl, input.mediaId)
    .first<{ id: string }>();
  if (!existing) {
    return {
      reason: 'Media metadata has not reached the mother service yet.',
      stored: false,
    };
  }

  const localObjectKey = await buildLocalMediaObjectKey(input.serviceUrl, input.objectKey);
  const syncedAt = nowIso();
  await env.MEDIA_BUCKET.put(localObjectKey, input.body, {
    customMetadata: {
      byteSize: String(Math.max(0, Math.trunc(input.byteSize))),
      mirrorSource: 'nct-backend',
      sourceMediaId: input.mediaId,
      sourceObjectKey: input.objectKey,
      sourceServiceHash: (await sha256(input.serviceUrl.trim())).slice(0, 24),
      syncedAt,
    },
    httpMetadata: {
      contentType: input.contentType,
    },
  });

  const publicUrl = buildLocalMediaPublicUrl(input.requestUrl, localObjectKey);
  await env.DB.prepare(
    `
      UPDATE school_media
      SET local_object_key = ?,
          public_url = ?,
          object_synced_at = ?
      WHERE source_service_url = ?
        AND source_media_id = ?
    `,
  )
    .bind(localObjectKey, publicUrl, syncedAt, input.serviceUrl, input.mediaId)
    .run();

  return {
    localObjectKey,
    publicUrl,
    stored: true,
  };
}

export async function readMediaObject(
  env: Env,
  objectKey: string,
): Promise<R2ObjectBody | null> {
  if (!hasMediaBucket(env) || !isSafeLocalMediaObjectKey(objectKey)) {
    return null;
  }

  return env.MEDIA_BUCKET.get(objectKey);
}

async function readSystemState<T extends object>(
  db: D1Database,
  key: string,
): Promise<T | null> {
  const row = await db.prepare(
    `
      SELECT value_json
      FROM system_state
      WHERE key = ?
      LIMIT 1
    `,
  )
    .bind(key)
    .first<{ value_json: string }>();
  if (!row) return null;

  try {
    const parsed = JSON.parse(row.value_json) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as T
      : null;
  } catch {
    return null;
  }
}

async function writeSystemState(
  db: D1Database,
  key: string,
  value: object,
): Promise<void> {
  await db.prepare(
    `
      INSERT INTO system_state (
        key,
        value_json,
        updated_at
      )
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        value_json = excluded.value_json,
        updated_at = excluded.updated_at
    `,
  )
    .bind(key, JSON.stringify(value), nowIso())
    .run();
}

export async function calculateMediaBucketUsage(
  env: Env,
): Promise<{
  objectCount: number;
  totalBytes: number;
}> {
  if (!hasMediaBucket(env)) {
    return {
      objectCount: 0,
      totalBytes: 0,
    };
  }

  let cursor: string | undefined;
  let objectCount = 0;
  let totalBytes = 0;
  do {
    const listed = await env.MEDIA_BUCKET.list({
      cursor,
      limit: 1000,
      prefix: 'sub-media/',
    });
    for (const object of listed.objects) {
      objectCount += 1;
      totalBytes += Number(object.size ?? 0);
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);

  return {
    objectCount,
    totalBytes,
  };
}

function formatGiB(bytes: number): string {
  return (bytes / (1024 * 1024 * 1024)).toFixed(2);
}

async function sendCapacityAlertEmail(
  env: Env,
  usage: {
    objectCount: number;
    totalBytes: number;
  },
  thresholdBytes: number,
): Promise<'sent' | 'skipped'> {
  const to = env.MEDIA_CAPACITY_ALERT_EMAIL_TO?.trim() || env.EXPORT_EMAIL_TO?.trim();
  const from = env.MEDIA_CAPACITY_ALERT_EMAIL_FROM?.trim() || env.EXPORT_EMAIL_FROM?.trim();
  if (!env.RESEND_API_KEY || !to || !from) {
    return 'skipped';
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.RESEND_API_KEY}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      from,
      to: [to],
      subject: `${env.APP_NAME ?? 'NCT API SQL'} R2 media bucket capacity alert`,
      html: [
        '<p>The mother media R2 bucket has reached the configured capacity threshold.</p>',
        `<p>Used: <strong>${formatGiB(usage.totalBytes)} GiB</strong> across ${usage.objectCount} object(s).</p>`,
        `<p>Threshold: <strong>${formatGiB(thresholdBytes)} GiB</strong>.</p>`,
      ].join(''),
    }),
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Resend email failed: ${response.status} ${errorText}`);
  }

  return 'sent';
}

export async function checkMediaBucketCapacity(
  env: Env,
): Promise<{
  alertSent: boolean;
  emailStatus: 'not_needed' | 'sent' | 'skipped';
  objectCount: number;
  thresholdBytes: number;
  totalBytes: number;
}> {
  const usage = await calculateMediaBucketUsage(env);
  const thresholdBytes = readPositiveNumber(
    env.MEDIA_CAPACITY_ALERT_BYTES,
    DEFAULT_CAPACITY_ALERT_BYTES,
  );
  if (usage.totalBytes < thresholdBytes) {
    return {
      alertSent: false,
      emailStatus: 'not_needed',
      objectCount: usage.objectCount,
      thresholdBytes,
      totalBytes: usage.totalBytes,
    };
  }

  const minIntervalMs = readPositiveNumber(
    env.MEDIA_CAPACITY_ALERT_MIN_INTERVAL_MS,
    DEFAULT_CAPACITY_ALERT_MIN_INTERVAL_MS,
  );
  const previous = await readSystemState<CapacityAlertState>(
    env.DB,
    CAPACITY_ALERT_STATE_KEY,
  );
  const lastAlertMs = previous?.lastAlertAt ? Date.parse(previous.lastAlertAt) : 0;
  if (Number.isFinite(lastAlertMs) && Date.now() - lastAlertMs < minIntervalMs) {
    return {
      alertSent: false,
      emailStatus: 'skipped',
      objectCount: usage.objectCount,
      thresholdBytes,
      totalBytes: usage.totalBytes,
    };
  }

  const emailStatus = await sendCapacityAlertEmail(env, usage, thresholdBytes);
  if (emailStatus === 'sent') {
    await writeSystemState(env.DB, CAPACITY_ALERT_STATE_KEY, {
      lastAlertAt: nowIso(),
      objectCount: usage.objectCount,
      thresholdBytes,
      totalBytes: usage.totalBytes,
    });
  }

  return {
    alertSent: emailStatus === 'sent',
    emailStatus,
    objectCount: usage.objectCount,
    thresholdBytes,
    totalBytes: usage.totalBytes,
  };
}
