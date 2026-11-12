import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { sha256Hex, sha256HexOfBytes } from '../src/index.js';

describe('sha256', () => {
  it('matches Node for text, including non-ASCII', () => {
    for (const text of [
      '',
      'abc',
      'Kedai Mamak Ali',
      'café 🍛 日本',
      'x'.repeat(10_000),
    ]) {
      expect(sha256Hex(text)).toBe(
        createHash('sha256').update(text, 'utf8').digest('hex'),
      );
    }
  });

  it('matches Node for bytes and the well-known test vector', () => {
    const bytes = randomBytes(5000);
    expect(sha256HexOfBytes(bytes)).toBe(
      createHash('sha256').update(bytes).digest('hex'),
    );
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});
