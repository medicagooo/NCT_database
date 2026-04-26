import { afterEach, describe, expect, it, vi } from 'vitest';
import { hmacSha256, sha256 } from './crypto';
import { verifySubServiceToken } from './data';

const SUB_AUTH_TOKEN_ALGORITHM = 'NCT-MOTHER-AUTH-HMAC-SHA256-T30-V1';
const SUB_AUTH_TOKEN_STEP_MS = 30 * 1000;

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

function createClientRow(
  overrides: Partial<DownstreamClientRow> = {},
): DownstreamClientRow {
  return {
    id: 1,
    entry_kind: 'sub-report',
    client_name: 'NCT API SQL Sub',
    callback_url: 'sub-report:https://sub.example.com',
    client_version: 0,
    last_sync_version: 0,
    last_seen_at: '2026-04-24T00:00:00.000Z',
    last_push_at: null,
    last_status: 'reported',
    last_response_code: 202,
    last_error: null,
    service_url: 'https://sub.example.com',
    databack_version: 0,
    report_count: 1,
    reported_at: '2026-04-24T00:00:00.000Z',
    payload_json: null,
    last_pull_version: 0,
    last_pull_at: null,
    last_pull_status: null,
    last_pull_response_code: null,
    last_pull_error: null,
    auth_failure_count: 0,
    blacklisted_at: null,
    auth_token_hash: null,
    auth_issued_at: '2026-04-24T00:00:00.000Z',
    auth_last_success_at: null,
    auth_last_failure_at: null,
    ...overrides,
  };
}

function createAuthDb(row: DownstreamClientRow) {
  const state = {
    row: {
      ...row,
    },
  };

  const db = {
    prepare(sql: string) {
      return {
        bind(...params: unknown[]) {
          return {
            first: async () => {
              if (sql.includes('WHERE service_url = ?')) {
                return state.row.service_url === params[0]
                  || state.row.callback_url === params[1]
                  ? { ...state.row }
                  : null;
              }

              if (sql.includes('WHERE id = ?')) {
                return Number(params[0]) === state.row.id
                  ? { ...state.row }
                  : null;
              }

              throw new Error(`Unexpected bound first SQL: ${sql}`);
            },
            run: async () => {
              if (sql.includes('SET auth_failure_count = ?')) {
                state.row.auth_failure_count = Number(params[0]);
                state.row.auth_last_failure_at = String(params[1]);
                state.row.blacklisted_at =
                  state.row.blacklisted_at ?? (params[2] ? String(params[2]) : null);
                state.row.last_response_code = Number(params[3]);
                state.row.last_error = String(params[4]);
                return {
                  success: true,
                };
              }

              if (sql.includes('SET auth_failure_count = 0')) {
                state.row.auth_failure_count = 0;
                state.row.auth_last_success_at = String(params[0]);
                state.row.last_seen_at = String(params[1]);
                state.row.last_error = null;
                return {
                  success: true,
                };
              }

              throw new Error(`Unexpected bound run SQL: ${sql}`);
            },
          };
        },
      };
    },
  } as unknown as D1Database;

  return {
    db,
    state,
  };
}

async function createRotatingToken(
  serviceUrl: string,
  nowMs = Date.now(),
): Promise<string> {
  return hmacSha256(
    [
      SUB_AUTH_TOKEN_ALGORITHM,
      serviceUrl,
      String(Math.floor(nowMs / SUB_AUTH_TOKEN_STEP_MS)),
    ].join('\n'),
    serviceUrl,
  );
}

afterEach(() => {
  vi.useRealTimers();
});

describe('verifySubServiceToken', () => {
  it('authenticates the sub identity from a 30-second rotating token', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-04-26T00:00:10.000Z'));
    const serviceUrl = 'https://sub.example.com';
    const token = await createRotatingToken(serviceUrl);
    const { db, state } = createAuthDb(
      createClientRow({
        auth_failure_count: 2,
        auth_token_hash: await sha256(serviceUrl),
      }),
    );

    const result = await verifySubServiceToken(
      {
        DB: db,
      } as Env,
      serviceUrl,
      token,
      5,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.stored).not.toBeNull();
    if (!result.stored) {
      return;
    }
    expect(result.stored.serviceUrl).toBe('https://sub.example.com');
    expect(state.row.auth_failure_count).toBe(0);
    expect(state.row.auth_last_success_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(state.row.last_error).toBeNull();
  });

  it('allows first report authentication before the sub row exists', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-04-26T00:00:10.000Z'));
    const serviceUrl = 'https://new-sub.example.com';
    const token = await createRotatingToken(serviceUrl);
    const { db } = createAuthDb(
      createClientRow({
        callback_url: 'sub-report:https://other.example.com',
        service_url: 'https://other.example.com',
      }),
    );

    const result = await verifySubServiceToken(
      {
        DB: db,
      } as Env,
      serviceUrl,
      token,
      5,
      {
        allowUnregistered: true,
      },
    );

    expect(result).toEqual({
      ok: true,
      stored: null,
    });
  });

  it('rejects rotating tokens derived for a different service URL', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-04-26T00:00:10.000Z'));
    const token = await createRotatingToken('https://sub.example.com');
    const { db, state } = createAuthDb(
      createClientRow({
        auth_token_hash: await sha256('https://spoofed.example.com'),
        callback_url: 'sub-report:https://spoofed.example.com',
        service_url: 'https://spoofed.example.com',
      }),
    );

    const result = await verifySubServiceToken(
      {
        DB: db,
      } as Env,
      'https://spoofed.example.com',
      token,
      3,
    );

    expect(result).toEqual({
      ok: false,
      reason: 'Sub service token is invalid.',
      status: 401,
    });
    expect(state.row.auth_failure_count).toBe(0);
    expect(state.row.last_response_code).toBe(202);
    expect(state.row.blacklisted_at).toBeNull();
  });

  it('does not blacklist a registered sub when an unrelated invalid token spoofs its URL', async () => {
    const { db, state } = createAuthDb(
      createClientRow({
        auth_token_hash: await sha256('https://sub.example.com'),
      }),
    );

    const result = await verifySubServiceToken(
      {
        DB: db,
      } as Env,
      'https://sub.example.com',
      'invalid-token',
      1,
    );

    expect(result).toEqual({
      ok: false,
      reason: 'Sub service token is invalid.',
      status: 401,
    });
    expect(state.row.auth_failure_count).toBe(0);
    expect(state.row.blacklisted_at).toBeNull();
    expect(state.row.last_error).toBeNull();
  });
});
