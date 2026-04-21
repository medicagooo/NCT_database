import { describe, expect, it } from 'vitest';
import {
  ensureDynamicColumns,
  extractDynamicColumns,
  serializeDynamicColumnValue,
} from './dynamic-schema';

function createFakeDb(
  initialColumns: string[] = [],
  duplicateColumns: Set<string> = new Set(),
) {
  const columns = new Set(initialColumns);
  const sqlLog: string[] = [];

  const db = {
    prepare(sql: string) {
      return {
        all: async () => {
          sqlLog.push(sql);
          return {
            results: Array.from(columns).map((name) => ({ name })),
          };
        },
        run: async () => {
          sqlLog.push(sql);
          const match = sql.match(/ADD COLUMN "((?:[^"]|"")+)"/);
          const columnName = match?.[1]?.replaceAll('""', '"');

          if (!columnName) {
            throw new Error(`Unexpected SQL: ${sql}`);
          }

          if (duplicateColumns.has(columnName)) {
            throw new Error('duplicate column name');
          }

          columns.add(columnName);
          return {
            success: true,
          };
        },
      };
    },
  } as unknown as D1Database;

  return {
    db,
    columns,
    sqlLog,
  };
}

describe('dynamic schema helpers', () => {
  it('adds missing dynamic columns once per trimmed field name', async () => {
    const { db, sqlLog } = createFakeDb([
      'id',
      'payload_json',
    ]);

    const mappings = await ensureDynamicColumns(
      db,
      'raw_records',
      'payload',
      [' Email ', 'full name', 'Email', 'full name'],
    );

    expect([...mappings.keys()]).toEqual([
      'Email',
      'full name',
    ]);
    expect([...mappings.values()]).toHaveLength(2);
    expect(
      sqlLog.filter((sql) => sql.includes('ALTER TABLE')),
    ).toHaveLength(2);
  });

  it('reuses existing columns and tolerates duplicate-column races', async () => {
    const seedDb = createFakeDb();
    const seedMappings = await ensureDynamicColumns(
      seedDb.db,
      'raw_records',
      'payload',
      ['Email', 'phone'],
    );
    const emailColumn = seedMappings.get('Email');
    const phoneColumn = seedMappings.get('phone');

    expect(emailColumn).toBeTruthy();
    expect(phoneColumn).toBeTruthy();

    const reusedDb = createFakeDb([emailColumn!], new Set([phoneColumn!]));
    const mappings = await ensureDynamicColumns(
      reusedDb.db,
      'raw_records',
      'payload',
      ['Email', 'phone'],
    );

    expect(mappings.get('Email')).toBe(emailColumn);
    expect(mappings.get('phone')).toBe(phoneColumn);
    expect(
      reusedDb.sqlLog.filter((sql) => sql.includes('ALTER TABLE')),
    ).toHaveLength(1);
  });

  it('serializes complex values and extracts stored dynamic columns', async () => {
    const { db } = createFakeDb();
    const mappings = await ensureDynamicColumns(
      db,
      'raw_records',
      'payload',
      ['email', 'notes'],
    );
    const emailColumn = mappings.get('email');
    const notesColumn = mappings.get('notes');

    expect(
      serializeDynamicColumnValue({
        nested: true,
        list: [1, 2],
      }),
    ).toBe('{"list":[1,2],"nested":true}');
    expect(serializeDynamicColumnValue(null)).toBeNull();

    const extracted = extractDynamicColumns(
      {
        [emailColumn!]: 'demo@example.com',
        [notesColumn!]: '{"list":[1,2],"nested":true}',
      },
      'payload',
      ['notes', 'email'],
    );

    expect(extracted).toEqual({
      email: 'demo@example.com',
      notes: '{"list":[1,2],"nested":true}',
    });
  });
});
