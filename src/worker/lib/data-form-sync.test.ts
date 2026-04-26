import { afterEach, describe, expect, it, vi } from 'vitest';

const { encryptObjectMock, hmacSha256Mock, sha256Mock } = vi.hoisted(() => ({
  encryptObjectMock: vi.fn(),
  hmacSha256Mock: vi.fn(),
  sha256Mock: vi.fn(),
}));

vi.mock('./crypto', () => ({
  decryptObject: vi.fn(),
  encryptObject: encryptObjectMock,
  hmacSha256: hmacSha256Mock,
  sha256: sha256Mock,
}));

import {
  ingestRecords,
  ingestSubFormRecords,
  pushSecureRecordsToRegisteredSubs,
} from './data';

type InsertCall = {
  columns: string[];
  params: unknown[];
  table: string;
};

type UpdateCall = {
  columns: string[];
  params: unknown[];
  table: string;
};

type DbRow = Record<string, unknown>;

function readQuotedName(value: string): string {
  return value.replaceAll('""', '"');
}

function readInsertColumns(sql: string, tableName: string): string[] {
  const match = sql.match(
    new RegExp(`INSERT INTO "${tableName}" \\(([\\s\\S]*?)\\)\\s*VALUES`),
  );
  if (!match) {
    throw new Error(`Could not read insert columns from SQL: ${sql}`);
  }

  return Array.from(match[1]!.matchAll(/"((?:[^"]|"")+)"/g)).map((item) =>
    readQuotedName(item[1]!),
  );
}

function readUpdateColumns(sql: string, tableName: string): string[] {
  const match = sql.match(
    new RegExp(`UPDATE "${tableName}"\\s+SET([\\s\\S]*?)\\s+WHERE`),
  );
  if (!match) {
    throw new Error(`Could not read update columns from SQL: ${sql}`);
  }

  return Array.from(match[1]!.matchAll(/"((?:[^"]|"")+)"/g)).map((item) =>
    readQuotedName(item[1]!),
  );
}

function cloneRow<T extends DbRow>(row: T): T {
  return { ...row };
}

function findRowById(rows: Iterable<DbRow>, id: unknown): DbRow | null {
  const resolvedId = String(id);
  for (const row of rows) {
    if (String(row.id) === resolvedId) {
      return row;
    }
  }

  return null;
}

function applyColumnValues(
  row: DbRow,
  columns: string[],
  params: unknown[],
) {
  columns.forEach((column, index) => {
    row[column] = params[index];
  });
}

function createDownstreamClientRow(
  overrides: Partial<DbRow> = {},
): DbRow {
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

function createMotherFormSyncDb(options: {
  downstreamRows?: DbRow[];
  rawRows?: DbRow[];
  secureRows?: DbRow[];
} = {}) {
  const columnsByTable = new Map<string, Set<string>>([
    [
      'raw_records',
      new Set([
        'id',
        'record_key',
        'source',
        'version',
        'payload_json',
        'payload_hash',
        'received_at',
        'processed_at',
        'created_at',
        'updated_at',
      ]),
    ],
    [
      'secure_records',
      new Set([
        'id',
        'raw_record_id',
        'record_key',
        'version',
        'key_version',
        'public_json',
        'encrypted_json',
        'encrypt_fields_json',
        'fingerprint',
        'created_at',
        'updated_at',
      ]),
    ],
  ]);
  const insertCalls: InsertCall[] = [];
  const updateCalls: UpdateCall[] = [];
  const rawRows = new Map<string, DbRow>();
  const secureRows = new Map<string, DbRow>();
  const downstreamRows = (options.downstreamRows ?? []).map(cloneRow);

  for (const row of options.rawRows ?? []) {
    rawRows.set(String(row.record_key), { ...row });
  }

  for (const row of options.secureRows ?? []) {
    secureRows.set(String(row.record_key), { ...row });
  }

  const readCurrentSecureVersion = () =>
    Math.max(
      0,
      ...Array.from(secureRows.values()).map((row) => Number(row.version ?? 0)),
    );

  const readTableColumns = (sql: string) => {
    const tableName = sql.match(/PRAGMA table_info\("((?:[^"]|"")+)"\)/)?.[1];
    const columns = tableName
      ? columnsByTable.get(readQuotedName(tableName))
      : null;

    if (!columns) {
      throw new Error(`Unexpected PRAGMA SQL: ${sql}`);
    }

    return {
      results: Array.from(columns).map((name) => ({ name })),
    };
  };

  const addDynamicColumn = (sql: string) => {
    const match = sql.match(
      /ALTER TABLE "((?:[^"]|"")+)".*ADD COLUMN "((?:[^"]|"")+)"/s,
    );
    if (!match) {
      throw new Error(`Unexpected ALTER SQL: ${sql}`);
    }

    const tableName = readQuotedName(match[1]!);
    const columnName = readQuotedName(match[2]!);
    columnsByTable.get(tableName)?.add(columnName);
  };

  const insertRow = (
    sql: string,
    params: unknown[],
    tableName: 'raw_records' | 'secure_records',
  ) => {
    const columns = readInsertColumns(sql, tableName);
    const row = Object.fromEntries(
      columns.map((column, index) => [column, params[index]]),
    );

    if (tableName === 'raw_records') {
      rawRows.set(String(row.record_key), row);
    } else {
      secureRows.set(String(row.record_key), row);
    }

    insertCalls.push({
      columns,
      params,
      table: tableName,
    });
  };

  const updateRow = (
    sql: string,
    params: unknown[],
    tableName: 'raw_records' | 'secure_records',
  ) => {
    const columns = readUpdateColumns(sql, tableName);
    const rows = tableName === 'raw_records'
      ? rawRows.values()
      : secureRows.values();
    const row = findRowById(rows, params[columns.length]);
    if (!row) {
      throw new Error(`Could not find ${tableName} row for SQL: ${sql}`);
    }

    applyColumnValues(row, columns, params);
    updateCalls.push({
      columns,
      params,
      table: tableName,
    });
  };

  const updateDownstreamClient = (sql: string, params: unknown[]) => {
    const row = downstreamRows.find((item) =>
      Number(item.id) === Number(params[params.length - 1]),
    );
    if (!row) {
      throw new Error(`Could not find downstream row for SQL: ${sql}`);
    }

    if (sql.includes('SET last_sync_version = ?')) {
      row.last_sync_version = params[0];
      row.last_push_at = params[1];
      row.last_status = 'pushed';
      row.last_response_code = params[2];
      row.last_error = null;
      return;
    }

    if (sql.includes("last_status = 'up-to-date'")) {
      row.last_status = 'up-to-date';
      row.last_response_code = 204;
      row.last_error = null;
      return;
    }

    if (sql.includes("last_status = 'push-failed'")) {
      row.last_status = 'push-failed';
      row.last_response_code = params[0];
      row.last_error = params[1];
      return;
    }

    if (sql.includes("last_status = 'push-error'")) {
      row.last_status = 'push-error';
      row.last_response_code = null;
      row.last_error = params[0];
      return;
    }

    throw new Error(`Unexpected downstream update SQL: ${sql}`);
  };

  const db = {
    prepare(sql: string) {
      return {
        all: async () => {
          if (sql.includes('PRAGMA table_info')) {
            return readTableColumns(sql);
          }

          if (sql.includes('FROM downstream_clients')) {
            return {
              results: downstreamRows
                .filter((row) =>
                  row.entry_kind === 'sub-report'
                  && row.service_url
                  && row.blacklisted_at === null,
                )
                .map(cloneRow),
            };
          }

          throw new Error(`Unexpected unbound all SQL: ${sql}`);
        },
        bind(...params: unknown[]) {
          return {
            all: async () => {
              if (
                sql.includes('FROM secure_records')
                && sql.includes('WHERE version > ?')
              ) {
                return {
                  results: Array.from(secureRows.values())
                    .filter((row) => Number(row.version ?? 0) > Number(params[0]))
                    .sort((left, right) =>
                      Number(left.version ?? 0) - Number(right.version ?? 0),
                    )
                    .map(cloneRow),
                };
              }

              throw new Error(`Unexpected bound all SQL: ${sql}`);
            },
            first: async () => {
              if (sql.includes('FROM raw_records')) {
                return rawRows.get(String(params[0])) ?? null;
              }

              if (sql.includes('FROM secure_records')) {
                return secureRows.get(String(params[0])) ?? null;
              }

              throw new Error(`Unexpected bound first SQL: ${sql}`);
            },
            run: async () => {
              if (sql.includes('INSERT INTO "raw_records"')) {
                insertRow(sql, params, 'raw_records');
                return { success: true };
              }

              if (sql.includes('INSERT INTO "secure_records"')) {
                insertRow(sql, params, 'secure_records');
                return { success: true };
              }

              if (sql.includes('UPDATE "raw_records"')) {
                updateRow(sql, params, 'raw_records');
                return { success: true };
              }

              if (sql.includes('UPDATE "secure_records"')) {
                updateRow(sql, params, 'secure_records');
                return { success: true };
              }

              if (sql.includes('UPDATE raw_records')) {
                const row = findRowById(rawRows.values(), params[2]);
                if (!row) {
                  throw new Error(`Could not find raw row for SQL: ${sql}`);
                }

                row.processed_at = params[0];
                row.updated_at = params[1];
                updateCalls.push({
                  columns: ['processed_at', 'updated_at'],
                  params,
                  table: 'raw_records',
                });
                return { success: true };
              }

              if (sql.includes('UPDATE downstream_clients')) {
                updateDownstreamClient(sql, params);
                return { success: true };
              }

              throw new Error(`Unexpected bound run SQL: ${sql}`);
            },
          };
        },
        first: async () => {
          if (sql.includes('SELECT COALESCE(MAX(version), 0) AS version')) {
            return { version: readCurrentSecureVersion() };
          }

          throw new Error(`Unexpected unbound first SQL: ${sql}`);
        },
        run: async () => {
          if (sql.includes('ALTER TABLE')) {
            addDynamicColumn(sql);
            return { success: true };
          }

          throw new Error(`Unexpected unbound run SQL: ${sql}`);
        },
      };
    },
  } as unknown as D1Database;

  return {
    db,
    insertCalls,
    state: {
      downstreamRows,
      rawRows,
      secureRows,
    },
    updateCalls,
  };
}

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe('ingestSubFormRecords', () => {
  it('stores future questionnaire fields from sub sync payloads in mother D1', async () => {
    sha256Mock.mockImplementation(async () => '000001'.padEnd(64, '0'));
    encryptObjectMock.mockImplementation(async (payload: unknown) => ({
      algorithm: 'AES-GCM',
      ciphertext: JSON.stringify(payload),
      iv: 'mock-iv',
    }));
    const { db, insertCalls } = createMotherFormSyncDb();
    const submittedFields = {
      future_multi: ['第一项', '第二项'],
      future_question: '未来新增答案',
      nested: {
        child: '值',
      },
    };

    const result = await ingestSubFormRecords(
      {
        DB: db,
        ENCRYPTION_KEY: 'not-used-by-mocked-crypto',
      } as Env,
      {
        records: [
          {
            databackFingerprint: 'sub-fingerprint',
            databackVersion: 8,
            payload: {
              name: '测试机构',
              submittedFields,
            },
            recordKey: 'form:future-field',
            updatedAt: '2026-04-24T12:00:00.000Z',
          },
        ],
        serviceUrl: 'https://sub.example.com',
      },
    );

    expect(result).toEqual([
      {
        databackFingerprint: '000001'.padEnd(64, '0'),
        motherVersion: 2,
        recordKey: 'form:future-field',
        updated: true,
      },
    ]);

    const rawInsert = insertCalls.find((item) => item.table === 'raw_records');
    const secureInsert = insertCalls.find((item) => item.table === 'secure_records');
    expect(rawInsert).toBeTruthy();
    expect(secureInsert).toBeTruthy();

    const rawPayload = JSON.parse(
      String(rawInsert!.params[rawInsert!.columns.indexOf('payload_json')]),
    );
    const publicPayload = JSON.parse(
      String(secureInsert!.params[secureInsert!.columns.indexOf('public_json')]),
    );

    expect(rawPayload).toEqual({
      name: '测试机构',
      submittedFields,
    });
    expect(publicPayload).toEqual({
      name: '测试机构',
      submittedFields,
    });
    expect(rawInsert!.params[rawInsert!.columns.indexOf('version')]).toBe(2);
    expect(secureInsert!.params[secureInsert!.columns.indexOf('version')]).toBe(2);
    expect(rawInsert!.params).toContain(JSON.stringify(submittedFields));
    expect(secureInsert!.params).toContain(JSON.stringify(submittedFields));
  });

  it('keeps raw updates, encrypted secure records, versions, and sub pushes in sync', async () => {
    hmacSha256Mock.mockResolvedValue('rotating-auth-token');
    sha256Mock.mockImplementation(async (value: string) => {
      if (value.includes('13900000000')) {
        return '000002'.padEnd(64, '0');
      }

      if (value.includes('13800000000')) {
        return '000001'.padEnd(64, '0');
      }

      return '000010'.padEnd(64, '0');
    });
    encryptObjectMock.mockImplementation(async (payload: unknown) => ({
      algorithm: 'AES-GCM',
      ciphertext: `encrypted:${Object.keys(payload as Record<string, unknown>).sort().join(',')}`,
      iv: 'mock-iv',
    }));
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(null, { status: 202 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const { db, state, updateCalls } = createMotherFormSyncDb({
      downstreamRows: [
        createDownstreamClientRow({
          service_url: 'https://sub.example.com',
        }),
      ],
    });
    const env = {
      DB: db,
      DEFAULT_ENCRYPT_FIELDS: 'name,contact',
      ENCRYPTION_KEY: 'not-used-by-mocked-crypto',
    } as Env;

    const [initial] = await ingestRecords(env, [
      {
        payload: {
          city: '广州',
          contact: '13800000000',
          name: '测试受害者',
        },
        recordKey: 'form:encrypted-record',
        source: 'manual-test',
      },
    ]);
    const [updated] = await ingestRecords(env, [
      {
        payload: {
          city: '深圳',
          contact: '13900000000',
          name: '测试受害者',
        },
        recordKey: 'form:encrypted-record',
        source: 'manual-test',
      },
    ]);

    expect(initial).toMatchObject({
      recordKey: 'form:encrypted-record',
      updated: true,
      version: 2,
    });
    expect(updated).toMatchObject({
      recordKey: 'form:encrypted-record',
      updated: true,
      version: 5,
    });

    const rawRow = state.rawRows.get('form:encrypted-record');
    const secureRow = state.secureRows.get('form:encrypted-record');
    expect(rawRow).toBeTruthy();
    expect(secureRow).toBeTruthy();
    expect(rawRow?.version).toBe(updated?.version);
    expect(secureRow?.version).toBe(updated?.version);
    expect(JSON.parse(String(rawRow?.payload_json))).toEqual({
      city: '深圳',
      contact: '13900000000',
      name: '测试受害者',
    });
    expect(JSON.parse(String(secureRow?.public_json))).toEqual({
      city: '深圳',
    });
    expect(JSON.parse(String(secureRow?.encrypt_fields_json))).toEqual([
      'name',
      'contact',
    ]);
    expect(JSON.parse(String(secureRow?.encrypted_json))).toEqual({
      algorithm: 'AES-GCM',
      ciphertext: 'encrypted:contact,name',
      iv: 'mock-iv',
    });
    expect(
      Object.entries(secureRow ?? {}).filter(([column]) =>
        column.startsWith('encrypted_'),
      ),
    ).toEqual(
      expect.arrayContaining([
        expect.arrayContaining([
          expect.stringMatching(/^encrypted_contact_/),
          JSON.stringify({
            algorithm: 'AES-GCM',
            ciphertext: 'encrypted:contact',
            iv: 'mock-iv',
          }),
        ]),
        expect.arrayContaining([
          expect.stringMatching(/^encrypted_name_/),
          JSON.stringify({
            algorithm: 'AES-GCM',
            ciphertext: 'encrypted:name',
            iv: 'mock-iv',
          }),
        ]),
      ]),
    );
    expect(encryptObjectMock).toHaveBeenCalledWith(
      {
        contact: '13900000000',
        name: '测试受害者',
      },
      'not-used-by-mocked-crypto',
    );
    expect(updateCalls.some((call) => call.table === 'raw_records')).toBe(true);
    expect(updateCalls.some((call) => call.table === 'secure_records')).toBe(true);

    const pushResults = await pushSecureRecordsToRegisteredSubs(env);

    expect(pushResults).toEqual([
      expect.objectContaining({
        currentVersion: 5,
        previousVersion: 0,
        pushed: true,
        pushUrl: 'https://sub.example.com/api/push/secure-records',
        responseCode: 202,
        serviceUrl: 'https://sub.example.com',
        status: 'pushed',
        totalRecords: 1,
      }),
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [pushUrl, requestInit] = fetchMock.mock.calls[0]!;
    expect(pushUrl).toBe('https://sub.example.com/api/push/secure-records');
    expect(requestInit?.method).toBe('POST');
    expect(requestInit?.headers).toMatchObject({
      authorization: 'Bearer rotating-auth-token',
      'content-type': 'application/json',
    });
    const pushedBody = JSON.parse(String(requestInit?.body));
    expect(pushedBody).toMatchObject({
      currentVersion: 5,
      mode: 'delta',
      previousVersion: 0,
      records: [
        {
          fingerprint: updated?.fingerprint,
          payload: {
            encryptFields: ['name', 'contact'],
            encryptedData: {
              algorithm: 'AES-GCM',
              ciphertext: 'encrypted:contact,name',
              iv: 'mock-iv',
            },
            keyVersion: 1,
            publicData: {
              city: '深圳',
            },
          },
          recordKey: 'form:encrypted-record',
          version: 5,
        },
      ],
      service: 'NCT API SQL',
      totalRecords: 1,
    });
    expect(JSON.stringify(pushedBody)).not.toContain('13900000000');
    expect(state.downstreamRows[0]?.last_sync_version).toBe(5);
    expect(state.downstreamRows[0]?.last_status).toBe('pushed');
  });
});
