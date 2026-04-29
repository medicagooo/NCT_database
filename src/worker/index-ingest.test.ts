import { afterEach, describe, expect, it, vi } from 'vitest';

const {
  assertAdminAuthMock,
  ingestSubFormRecordsMock,
  ingestSubMediaRecordsMock,
  ingestRecordsMock,
  isRecognizedSubServiceMock,
  listSchoolMediaRecordsMock,
  pushSecureRecordsToRegisteredSubsMock,
  recordSubReportMock,
  reviewSchoolMediaRecordMock,
  verifySubServiceTokenMock,
} = vi.hoisted(() => ({
  assertAdminAuthMock: vi.fn(),
  ingestSubFormRecordsMock: vi.fn(),
  ingestSubMediaRecordsMock: vi.fn(),
  ingestRecordsMock: vi.fn(),
  isRecognizedSubServiceMock: vi.fn(),
  listSchoolMediaRecordsMock: vi.fn(),
  pushSecureRecordsToRegisteredSubsMock: vi.fn(),
  recordSubReportMock: vi.fn(),
  reviewSchoolMediaRecordMock: vi.fn(),
  verifySubServiceTokenMock: vi.fn(),
}));

vi.mock('./lib/data', () => ({
  NCT_SUB_SERVICE_WATERMARK: 'nct-api-sql-sub:v1',
  getAdminSnapshot: vi.fn(),
  getPublicDataset: vi.fn(),
  getPublishedPayload: vi.fn(),
  getSubReportThrottleState: vi.fn(),
  ingestRecords: ingestRecordsMock,
  ingestSubFormRecords: ingestSubFormRecordsMock,
  ingestSubMediaRecords: ingestSubMediaRecordsMock,
  isRecognizedSubService: isRecognizedSubServiceMock,
  listSchoolMediaRecords: listSchoolMediaRecordsMock,
  pullDatabackFromRegisteredSubs: vi.fn(),
  pushSecureRecordsToRegisteredSubs: pushSecureRecordsToRegisteredSubsMock,
  rebuildSecureRecords: vi.fn(),
  recordSubReport: recordSubReportMock,
  reviewSchoolMediaRecord: reviewSchoolMediaRecordMock,
  verifySubServiceToken: verifySubServiceTokenMock,
}));

vi.mock('./lib/adminAuth', () => {
  class AdminAuthError extends Error {
    code: string;
    status: number;

    constructor(status: number, code: string, message: string) {
      super(message);
      this.code = code;
      this.status = status;
    }
  }

  return {
    AdminAuthError,
    assertAdminAuth: assertAdminAuthMock,
    deleteAdminSession: vi.fn(),
    getAdminAuthStatus: vi.fn(),
    loginAdminPassword: vi.fn(),
    setupAdminPassword: vi.fn(),
  };
});

import worker from './index';

afterEach(() => {
  vi.clearAllMocks();
});

describe('Console shell routes', () => {
  for (const path of ['/Console', '/Console/records', '/console', '/console/records']) {
    it(`serves the Console shell for ${path}`, async () => {
      const assetFetch = vi.fn().mockResolvedValue(
        new Response('<div id="root"></div>', {
          headers: {
            'content-type': 'text/html',
          },
        }),
      );
      const env = {
        ASSETS: {
          fetch: assetFetch,
        },
      } as unknown as Env;

      const response = await worker.fetch(
        new Request(`https://mother.example.com${path}`),
        env,
        {} as ExecutionContext,
      );

      expect(response.status).toBe(200);
      expect(await response.text()).toBe('<div id="root"></div>');
      expect(assetFetch).toHaveBeenCalledTimes(1);
      expect(
        (assetFetch.mock.calls[0]?.[0] as Request).url,
      ).toBe('https://mother.example.com/index.html');
    });
  }
});

describe('/api/ingest', () => {
  it('schedules secure record communication when raw ingest updates data', async () => {
    const pushPromise = Promise.resolve([
      {
        currentVersion: 8,
        lastPushAt: '2026-04-24T00:00:00.000Z',
        previousVersion: 0,
        pushed: true,
        pushUrl: 'https://sub.example.com/api/push/secure-records',
        responseCode: 202,
        serviceUrl: 'https://sub.example.com',
        status: 'pushed',
        totalRecords: 1,
      },
    ]);
    const env = {} as Env;
    const executionCtx = {
      passThroughOnException: vi.fn(),
      waitUntil: vi.fn(),
    } as unknown as ExecutionContext;

    assertAdminAuthMock.mockResolvedValue(null);
    ingestRecordsMock.mockResolvedValue([
      {
        fingerprint: 'fingerprint-1',
        rawRecordId: 'raw-1',
        recordKey: 'form:updated-record',
        secureRecordId: 'secure-1',
        updated: true,
        version: 8,
      },
    ]);
    pushSecureRecordsToRegisteredSubsMock.mockReturnValue(pushPromise);

    const response = await worker.fetch(
      new Request('https://mother.example.com/api/ingest', {
        body: JSON.stringify({
          records: [
            {
              payload: {
                contact: '13900000000',
                name: '测试受害者',
              },
              recordKey: 'form:updated-record',
            },
          ],
        }),
        headers: {
          'content-type': 'application/json',
        },
        method: 'POST',
      }),
      env,
      executionCtx,
    );
    const body = await response.json() as {
      updatedCount: number;
    };

    expect(response.status).toBe(200);
    expect(body.updatedCount).toBe(1);
    expect(assertAdminAuthMock).toHaveBeenCalled();
    expect(ingestRecordsMock).toHaveBeenCalledWith(env, [
      {
        payload: {
          contact: '13900000000',
          name: '测试受害者',
        },
        recordKey: 'form:updated-record',
      },
    ]);
    expect(pushSecureRecordsToRegisteredSubsMock).toHaveBeenCalledWith(env);
    expect(executionCtx.waitUntil).toHaveBeenCalledWith(pushPromise);
  });
});

describe('/api/sub/report', () => {
  it('returns a fake success response for unverifiable sub reports without storing or pushing data', async () => {
    const env = {} as Env;
    const executionCtx = {
      passThroughOnException: vi.fn(),
      waitUntil: vi.fn(),
    } as unknown as ExecutionContext;

    isRecognizedSubServiceMock.mockReturnValue(true);
    verifySubServiceTokenMock.mockResolvedValue({
      ok: false,
      reason: 'Sub service token is invalid.',
      status: 401,
    });

    const response = await worker.fetch(
      new Request('https://mother.example.com/api/sub/report', {
        body: JSON.stringify({
          databackVersion: 7,
          reportCount: 2,
          reportedAt: '2026-04-26T00:00:00.000Z',
          service: 'Sub App',
          serviceUrl: 'https://sub.example.com',
          serviceWatermark: 'nct-api-sql-sub:v1',
        }),
        headers: {
          'content-type': 'application/json',
        },
        method: 'POST',
      }),
      env,
      executionCtx,
    );
    const body = await response.json() as {
      accepted: boolean;
      stored: {
        id: number;
        serviceUrl: string;
      };
    };

    expect(response.status).toBe(202);
    expect(body.accepted).toBe(true);
    expect(body.stored.serviceUrl).toBe('https://sub.example.com');
    expect(body.stored.id).toEqual(expect.any(Number));
    expect(recordSubReportMock).not.toHaveBeenCalled();
    expect(pushSecureRecordsToRegisteredSubsMock).not.toHaveBeenCalled();
    expect(executionCtx.waitUntil).not.toHaveBeenCalled();
  });
});

describe('/api/sub/form-records', () => {
  it('returns fake per-record success for unverifiable form sync requests without ingesting data', async () => {
    const env = {} as Env;
    const executionCtx = {
      passThroughOnException: vi.fn(),
      waitUntil: vi.fn(),
    } as unknown as ExecutionContext;

    verifySubServiceTokenMock.mockResolvedValue({
      ok: false,
      reason: 'Sub service token is required.',
      status: 401,
    });

    const response = await worker.fetch(
      new Request('https://mother.example.com/api/sub/form-records', {
        body: JSON.stringify({
          records: [
            {
              databackFingerprint: 'real-fingerprint',
              databackVersion: 12,
              payload: {
                name: '测试机构',
              },
              recordKey: 'form:real-record',
              updatedAt: '2026-04-26T00:00:00.000Z',
            },
          ],
          serviceUrl: 'https://sub.example.com',
        }),
        headers: {
          'content-type': 'application/json',
        },
        method: 'POST',
      }),
      env,
      executionCtx,
    );
    const body = await response.json() as {
      accepted: boolean;
      results: Array<{
        databackFingerprint: string;
        motherVersion: number;
        recordKey: string;
        updated: boolean;
      }>;
    };

    expect(response.status).toBe(202);
    expect(body.accepted).toBe(true);
    expect(body.results).toHaveLength(1);
    expect(body.results[0]).toMatchObject({
      motherVersion: 12,
      updated: true,
    });
    expect(body.results[0]?.databackFingerprint).toMatch(/^accepted:/);
    expect(body.results[0]?.recordKey).toMatch(/^accepted:/);
    expect(ingestSubFormRecordsMock).not.toHaveBeenCalled();
    expect(pushSecureRecordsToRegisteredSubsMock).not.toHaveBeenCalled();
    expect(executionCtx.waitUntil).not.toHaveBeenCalled();
  });
});

describe('/api/sub/media-objects', () => {
  it('returns fake success for unverifiable media object sync requests without storing data', async () => {
    const put = vi.fn();
    const env = {
      MEDIA_BUCKET: {
        put,
      },
    } as unknown as Env;
    const executionCtx = {
      passThroughOnException: vi.fn(),
      waitUntil: vi.fn(),
    } as unknown as ExecutionContext;

    verifySubServiceTokenMock.mockResolvedValue({
      ok: false,
      reason: 'Sub service token is required.',
      status: 401,
    });

    const url = new URL('https://mother.example.com/api/sub/media-objects');
    url.searchParams.set('serviceUrl', 'https://sub.example.com');
    url.searchParams.set('mediaId', 'media-id');
    url.searchParams.set('objectKey', 'media/schools/demo/2026/media-id.png');
    url.searchParams.set('byteSize', '11');
    url.searchParams.set('contentType', 'image/png');
    const response = await worker.fetch(
      new Request(url, {
        body: 'media-bytes',
        headers: {
          authorization: 'Bearer invalid',
          'content-type': 'image/png',
        },
        method: 'POST',
      }),
      env,
      executionCtx,
    );
    const body = await response.json() as {
      accepted: boolean;
      stored: boolean;
    };

    expect(response.status).toBe(202);
    expect(body).toEqual({
      accepted: true,
      stored: false,
    });
    expect(put).not.toHaveBeenCalled();
  });
});
