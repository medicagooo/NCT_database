import { describe, expect, it } from 'vitest';
import { sha256 } from './crypto';
import { verifySubServiceToken } from './data';

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
  sub_service_encryption_public_key: string | null;
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
    last_status: 'bootstrapped',
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
    sub_service_encryption_public_key: null,
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
              if (sql.includes('WHERE auth_token_hash = ?')) {
                return state.row.auth_token_hash === params[0]
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

describe('verifySubServiceToken', () => {
  it('authenticates the sub identity from the token binding instead of the claimed URL alone', async () => {
    const token = 'bound-token';
    const { db, state } = createAuthDb(
      createClientRow({
        auth_failure_count: 2,
        auth_token_hash: await sha256(token),
      }),
    );

    const result = await verifySubServiceToken(
      db,
      'https://sub.example.com',
      token,
      5,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.stored.serviceUrl).toBe('https://sub.example.com');
    expect(state.row.auth_failure_count).toBe(0);
    expect(state.row.auth_last_success_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(state.row.last_error).toBeNull();
  });

  it('rejects requests whose claimed service URL does not match the token-bound identity', async () => {
    const token = 'bound-token';
    const { db, state } = createAuthDb(
      createClientRow({
        auth_token_hash: await sha256(token),
      }),
    );

    const result = await verifySubServiceToken(
      db,
      'https://spoofed.example.com',
      token,
      3,
    );

    expect(result).toEqual({
      ok: false,
      reason: 'Sub service identity does not match the claimed service URL.',
      status: 403,
    });
    expect(state.row.auth_failure_count).toBe(1);
    expect(state.row.last_response_code).toBe(403);
    expect(state.row.blacklisted_at).toBeNull();
  });

  it('does not blacklist a registered sub when an unrelated invalid token spoofs its URL', async () => {
    const { db, state } = createAuthDb(
      createClientRow({
        auth_token_hash: await sha256('real-bound-token'),
      }),
    );

    const result = await verifySubServiceToken(
      db,
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
