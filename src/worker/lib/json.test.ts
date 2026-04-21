import { describe, expect, it } from 'vitest';
import {
  parseJsonObject,
  parseStringArray,
  stableStringify,
  toJsonObject,
} from './json';

describe('json helpers', () => {
  it('sorts object keys recursively for stable serialization', () => {
    const normalized = toJsonObject({
      zebra: true,
      alpha: {
        second: 2,
        first: 1,
      },
    });

    expect(Object.keys(normalized)).toEqual(['alpha', 'zebra']);
    expect(
      Object.keys(normalized.alpha as Record<string, unknown>),
    ).toEqual(['first', 'second']);
    expect(
      stableStringify({
        zebra: true,
        alpha: {
          second: 2,
          first: 1,
        },
      }),
    ).toBe('{"alpha":{"first":1,"second":2},"zebra":true}');
  });

  it('parses stored JSON payloads back into normalized objects', () => {
    expect(
      parseJsonObject('{"b":2,"a":{"d":4,"c":3}}'),
    ).toEqual({
      a: {
        c: 3,
        d: 4,
      },
      b: 2,
    });
  });

  it('parses string arrays by trimming values and dropping invalid entries', () => {
    expect(
      parseStringArray('[" email ","",null,123,"phone"]'),
    ).toEqual(['email', 'phone']);
  });

  it('rejects non-object payloads', () => {
    expect(() => toJsonObject(['not', 'an', 'object'])).toThrow(
      'Payload must be a JSON object.',
    );
  });
});
