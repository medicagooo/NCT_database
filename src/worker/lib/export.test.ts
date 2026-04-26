import JSZip from 'jszip';
import { Buffer } from 'node:buffer';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AdminSnapshot } from '../../shared/types';

const { getAdminSnapshotMock } = vi.hoisted(() => ({
  getAdminSnapshotMock: vi.fn(),
}));

vi.mock('./data', () => ({
  getAdminSnapshot: getAdminSnapshotMock,
}));

import { exportSnapshot } from './export';

const sampleSnapshot: AdminSnapshot = {
  overview: {
    totals: {
      rawRecords: 1,
      secureRecords: 1,
      downstreamClients: 1,
      currentVersion: 7,
    },
    rawBySource: [
      {
        source: 'hospital-a',
        count: 1,
      },
    ],
    syncStatuses: [
      {
        status: 'ok',
        count: 1,
      },
    ],
    versionHistory: [
      {
        recordKey: 'patient-1',
        version: 7,
      },
    ],
  },
  rawRecords: [
    {
      dataSourceType: 'batch_query',
      id: 'raw-1',
      recordKey: 'patient-1',
      source: 'hospital-a',
      version: 7,
      payload: {
        email: 'demo@example.com',
        name: 'Zhang San',
      },
      payloadColumns: {
        email: 'payload_email_abc123',
      },
      payloadHash: 'hash-1',
      receivedAt: '2026-04-21T00:00:00.000Z',
      processedAt: '2026-04-21T00:01:00.000Z',
      createdAt: '2026-04-21T00:00:00.000Z',
      updatedAt: '2026-04-21T00:01:00.000Z',
    },
  ],
  secureRecords: [
    {
      dataSourceType: 'batch_query',
      id: 'secure-1',
      rawRecordId: 'raw-1',
      recordKey: 'patient-1',
      version: 7,
      keyVersion: 1,
      publicData: {
        city: 'Shanghai',
      },
      publicColumns: {
        city: 'public_city_def456',
      },
      encryptedData: {
        algorithm: 'AES-GCM',
        iv: 'iv-value',
        ciphertext: 'ciphertext-value',
      },
      encryptedColumns: {
        email: 'encrypted_email_xyz789',
      },
      encryptFields: ['email', 'name'],
      fingerprint: 'fingerprint-1',
      syncedAt: null,
      createdAt: '2026-04-21T00:00:00.000Z',
      updatedAt: '2026-04-21T00:01:00.000Z',
    },
  ],
  downstreamClients: [
    {
      id: 1,
      entryKind: 'sub-report',
      clientName: 'Sub Service',
      callbackUrl: 'https://sub.example.com/callback',
      clientVersion: 7,
      lastSyncVersion: 7,
      lastSeenAt: '2026-04-21T00:02:00.000Z',
      lastPushAt: '2026-04-21T00:02:00.000Z',
      lastStatus: 'ok',
      lastResponseCode: 200,
      lastError: null,
      serviceUrl: 'https://sub.example.com',
      databackVersion: 7,
      reportCount: 1,
      reportedAt: '2026-04-21T00:02:00.000Z',
      payload: {
        mode: 'delta',
      },
      lastPullVersion: 7,
      lastPullAt: '2026-04-21T00:02:00.000Z',
      lastPullStatus: 'ok',
      lastPullResponseCode: 200,
      lastPullError: null,
      authFailureCount: 0,
      blacklistedAt: null,
      authIssuedAt: '2026-04-21T00:00:00.000Z',
      authLastSuccessAt: '2026-04-21T00:02:00.000Z',
      authLastFailureAt: null,
    },
  ],
};

async function readZipEntries(buffer: ArrayBuffer | Uint8Array) {
  const zip = await JSZip.loadAsync(buffer);
  return Object.keys(zip.files).sort();
}

async function readZipJson(
  buffer: ArrayBuffer | Uint8Array,
  fileName: string,
) {
  const zip = await JSZip.loadAsync(buffer);
  return JSON.parse(await zip.file(fileName)!.async('string'));
}

describe('exportSnapshot', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    getAdminSnapshotMock.mockResolvedValue(sampleSnapshot);
    vi.stubGlobal('fetch', fetchMock);
    vi.stubGlobal('btoa', (value: string) =>
      Buffer.from(value, 'binary').toString('base64'),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('archives the snapshot to R2 and emails the zip attachment when configured', async () => {
    const putMock = vi.fn(async () => undefined);

    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ id: 'mail_123' }), {
        status: 200,
        headers: {
          'content-type': 'application/json',
        },
      }),
    );

    const env = {
      DB: {} as D1Database,
      EXPORT_BUCKET: {
        put: putMock,
      } as unknown as R2Bucket,
      RESEND_API_KEY: 'resend-token',
      EXPORT_EMAIL_TO: 'ops@example.com',
      EXPORT_EMAIL_FROM: 'Exports <exports@example.com>',
      APP_NAME: 'NCT API SQL',
    } as Env;

    const result = await exportSnapshot(env);

    expect(result.emailStatus).toBe('sent');
    expect(result.fileName).toMatch(/^d1-export-.*\.zip$/);
    expect(result.objectKey).toMatch(
      /^exports\/\d{4}-\d{2}-\d{2}\/d1-export-.*\.zip$/,
    );

    expect(putMock).toHaveBeenCalledTimes(1);
    const firstPutCall = putMock.mock.calls[0];
    expect(firstPutCall).toBeTruthy();
    const [objectKey, archiveBuffer, options] = firstPutCall! as unknown as [
      string,
      ArrayBuffer,
      {
        httpMetadata: {
          contentType: string;
          contentDisposition: string;
        };
        customMetadata: {
          generatedAt: string;
        };
      },
    ];

    expect(objectKey).toBe(result.objectKey);
    expect(options.httpMetadata.contentType).toBe('application/zip');
    expect(options.httpMetadata.contentDisposition).toBe(
      `attachment; filename="${result.fileName}"`,
    );
    expect(options.customMetadata.generatedAt).toMatch(
      /^\d{4}-\d{2}-\d{2}T/,
    );
    await expect(readZipEntries(archiveBuffer)).resolves.toEqual([
      'downstream_clients.csv',
      'downstream_clients.json',
      'overview.json',
      'raw_records.csv',
      'raw_records.json',
      'secure_records.csv',
      'secure_records.json',
      'snapshot.json',
    ]);
    await expect(
      readZipJson(archiveBuffer, 'snapshot.json'),
    ).resolves.toEqual(sampleSnapshot);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0] as [
      string,
      RequestInit,
    ];
    const payload = JSON.parse(String(init.body)) as {
      from: string;
      to: string[];
      subject: string;
      attachments: Array<{
        filename: string;
        content: string;
      }>;
    };

    expect(payload.from).toBe(env.EXPORT_EMAIL_FROM);
    expect(payload.to).toEqual([env.EXPORT_EMAIL_TO!]);
    expect(payload.subject).toContain('NCT API SQL D1 export');
    expect(payload.attachments[0]?.filename).toBe(result.fileName);

    const attachmentBytes = Uint8Array.from(
      Buffer.from(payload.attachments[0]!.content, 'base64'),
    );
    await expect(readZipEntries(attachmentBytes)).resolves.toEqual([
      'downstream_clients.csv',
      'downstream_clients.json',
      'overview.json',
      'raw_records.csv',
      'raw_records.json',
      'secure_records.csv',
      'secure_records.json',
      'snapshot.json',
    ]);
  });

  it('skips email delivery when resend settings are incomplete', async () => {
    const putMock = vi.fn(async () => undefined);
    const env = {
      DB: {} as D1Database,
      EXPORT_BUCKET: {
        put: putMock,
      } as unknown as R2Bucket,
      APP_NAME: 'NCT API SQL',
    } as Env;

    const result = await exportSnapshot(env);

    expect(result.emailStatus).toBe('skipped');
    expect(putMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('surfaces resend failures after the archive has been uploaded', async () => {
    const putMock = vi.fn(async () => undefined);

    fetchMock.mockResolvedValue(
      new Response('quota exceeded', {
        status: 429,
      }),
    );

    const env = {
      DB: {} as D1Database,
      EXPORT_BUCKET: {
        put: putMock,
      } as unknown as R2Bucket,
      RESEND_API_KEY: 'resend-token',
      EXPORT_EMAIL_TO: 'ops@example.com',
      EXPORT_EMAIL_FROM: 'Exports <exports@example.com>',
      APP_NAME: 'NCT API SQL',
    } as Env;

    await expect(exportSnapshot(env)).rejects.toThrow(
      'Resend email failed: 429 quota exceeded',
    );
    expect(putMock).toHaveBeenCalledTimes(1);
  });
});
