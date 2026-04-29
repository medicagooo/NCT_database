import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  calculateMediaBucketUsage,
  checkMediaBucketCapacity,
  isSafeLocalMediaObjectKey,
  isSafeMediaObjectKey,
} from './media-storage';

function createStateDb() {
  const state = new Map<string, string>();

  return {
    db: {
      prepare(sql: string) {
        return {
          bind(...params: unknown[]) {
            return {
              first: async () => {
                if (sql.includes('SELECT value_json')) {
                  const value = state.get(String(params[0]));
                  return value ? { value_json: value } : null;
                }
                throw new Error(`Unexpected first SQL: ${sql}`);
              },
              run: async () => {
                if (sql.includes('INSERT INTO system_state')) {
                  state.set(String(params[0]), String(params[1]));
                  return {};
                }
                throw new Error(`Unexpected run SQL: ${sql}`);
              },
            };
          },
        };
      },
    } as unknown as D1Database,
    state,
  };
}

describe('media R2 storage helpers', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('validates source and local media object keys', () => {
    expect(isSafeMediaObjectKey('media/schools/demo/file.png')).toBe(true);
    expect(isSafeMediaObjectKey('private/file.png')).toBe(false);
    expect(isSafeMediaObjectKey('media/../file.png')).toBe(false);
    expect(isSafeLocalMediaObjectKey('sub-media/source/media/schools/demo/file.png')).toBe(true);
    expect(isSafeLocalMediaObjectKey('media/schools/demo/file.png')).toBe(false);
  });

  it('calculates bucket usage across paginated R2 lists', async () => {
    const list = vi.fn()
      .mockResolvedValueOnce({
        cursor: 'next',
        objects: [
          { size: 3 },
          { size: 4 },
        ],
        truncated: true,
      })
      .mockResolvedValueOnce({
        objects: [
          { size: 5 },
        ],
        truncated: false,
      });

    await expect(calculateMediaBucketUsage({
      MEDIA_BUCKET: {
        list,
      } as unknown as R2Bucket,
    } as Env)).resolves.toEqual({
      objectCount: 3,
      totalBytes: 12,
    });
    expect(list).toHaveBeenCalledWith({
      cursor: undefined,
      limit: 1000,
      prefix: 'sub-media/',
    });
    expect(list).toHaveBeenCalledWith({
      cursor: 'next',
      limit: 1000,
      prefix: 'sub-media/',
    });
  });

  it('sends a capacity alert once the media bucket crosses the threshold', async () => {
    const { db, state } = createStateDb();
    const fetchMock = vi.fn(async () => Response.json({ id: 'email-id' }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await checkMediaBucketCapacity({
      APP_NAME: 'Mother',
      DB: db,
      EXPORT_EMAIL_FROM: 'alerts@example.com',
      EXPORT_EMAIL_TO: 'ops@example.com',
      MEDIA_BUCKET: {
        list: vi.fn(async () => ({
          objects: [
            { size: 12 },
          ],
          truncated: false,
        })),
      } as unknown as R2Bucket,
      MEDIA_CAPACITY_ALERT_BYTES: '10',
      RESEND_API_KEY: 'resend-key',
    } as Env);

    expect(result).toMatchObject({
      alertSent: true,
      emailStatus: 'sent',
      objectCount: 1,
      thresholdBytes: 10,
      totalBytes: 12,
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.resend.com/emails',
      expect.objectContaining({
        method: 'POST',
      }),
    );
    expect(state.has('media_bucket_capacity_alert')).toBe(true);
  });
});
