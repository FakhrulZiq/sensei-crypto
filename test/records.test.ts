import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  decryptBlob,
  decryptRecord,
  encryptBlob,
  encryptRecord,
  fromBase64,
  generateDataKey,
  toBase64,
} from '../src/index.js';
import {
  counting,
  nodeGcmDecrypt,
  nodeGcmEncrypt,
  scripted,
} from './helpers.js';

const dek = counting(32);
const context = {
  uid: 'uid-1',
  table: 'transactions',
  recordId: 'tx-1',
  kid: 'k_test0001',
};
const row = {
  id: 'tx-1',
  amount_sen: 1250,
  note: 'Nasi lemak 🍛 — café',
  lat: 3.139,
  lng: 101.6869,
  owed: false,
};

describe('records', () => {
  it('round-trips any JSON value', () => {
    for (const value of [
      row,
      'text',
      0,
      null,
      [],
      [1, { a: [true] }],
      { big: 'x'.repeat(60_000) },
    ]) {
      const envelope = encryptRecord(dek, context, value);
      expect(decryptRecord(dek, context, envelope)).toEqual(value);
    }
  });

  it('produces the envelope shape the server stores', () => {
    const envelope = encryptRecord(dek, context, row);
    expect(Object.keys(envelope).sort()).toEqual([
      'alg',
      'ct',
      'iv',
      'kid',
      'v',
    ]);
    expect(envelope).toMatchObject({ v: 1, alg: 'A256GCM', kid: 'k_test0001' });
    expect(fromBase64(envelope.iv)).toHaveLength(12);
    expect(fromBase64(envelope.ct).length).toBe(
      JSON.stringify(row).length +
        16 +
        (Buffer.byteLength(JSON.stringify(row)) - JSON.stringify(row).length),
    );
  });

  it('is plain AES-256-GCM: Node decrypts what we encrypt, and we decrypt what Node encrypts', () => {
    const iv = counting(12, 100);
    const envelope = encryptRecord(dek, context, row, scripted(iv));
    const plaintext = nodeGcmDecrypt(
      dek,
      iv,
      'uid-1|transactions|tx-1|v1',
      fromBase64(envelope.ct),
    );
    expect(JSON.parse(plaintext.toString())).toEqual(row);

    const nodeIv = counting(12, 50);
    const nodeCt = nodeGcmEncrypt(
      dek,
      nodeIv,
      'uid-1|transactions|tx-1|v1',
      Buffer.from(JSON.stringify(row)),
    );
    expect(
      decryptRecord(dek, context, {
        v: 1,
        alg: 'A256GCM',
        kid: context.kid,
        iv: toBase64(nodeIv),
        ct: toBase64(nodeCt),
      }),
    ).toEqual(row);
  });

  it('never contains the plaintext', () => {
    const { ct } = encryptRecord(dek, context, row);
    const raw = Buffer.from(fromBase64(ct)).toString('latin1');
    for (const secret of ['Nasi lemak', '1250', '101.6869', 'tx-1']) {
      expect(raw).not.toContain(secret);
      expect(ct).not.toContain(secret);
    }
  });

  it('uses a fresh IV every time', () => {
    const ivs = new Set(
      Array.from({ length: 2000 }, () => encryptRecord(dek, context, row).iv),
    );
    expect(ivs.size).toBe(2000);
  });

  describe('is bound to where it belongs', () => {
    const envelope = encryptRecord(dek, context, row);

    it.each([
      ['another user', { ...context, uid: 'uid-2' }],
      ['another table', { ...context, table: 'accounts' }],
      ['another record', { ...context, recordId: 'tx-2' }],
    ])('refuses to open under %s', (_label, wrong) => {
      expect(() => decryptRecord(dek, wrong, envelope)).toThrow();
    });

    it('refuses the wrong key', () => {
      expect(() =>
        decryptRecord(generateDataKey(), context, envelope),
      ).toThrow();
    });

    it('refuses a record the server rearranged: a row cannot be replayed as another row', () => {
      const other = encryptRecord(
        dek,
        { ...context, recordId: 'tx-2' },
        { id: 'tx-2' },
      );
      expect(() => decryptRecord(dek, context, other)).toThrow();
    });
  });

  describe('detects tampering', () => {
    const envelope = encryptRecord(dek, context, row);

    it('flips of any single ciphertext, tag or iv byte', () => {
      const ct = fromBase64(envelope.ct);
      for (const index of [
        0,
        1,
        Math.floor(ct.length / 2),
        ct.length - 17,
        ct.length - 16,
        ct.length - 1,
      ]) {
        const altered = ct.slice();
        altered[index] ^= 1;
        expect(() =>
          decryptRecord(dek, context, { ...envelope, ct: toBase64(altered) }),
        ).toThrow();
      }
      const iv = fromBase64(envelope.iv);
      iv[0] ^= 1;
      expect(() =>
        decryptRecord(dek, context, { ...envelope, iv: toBase64(iv) }),
      ).toThrow();
    });

    it('truncation and wrong versions', () => {
      expect(() =>
        decryptRecord(dek, context, {
          ...envelope,
          ct: toBase64(fromBase64(envelope.ct).slice(0, 8)),
        }),
      ).toThrow('Malformed');
      expect(() =>
        decryptRecord(dek, context, {
          ...envelope,
          ct: toBase64(fromBase64(envelope.ct).slice(0, -1)),
        }),
      ).toThrow();
      expect(() =>
        decryptRecord(dek, context, { ...envelope, v: 2 as 1 }),
      ).toThrow('Unsupported');
      expect(() =>
        decryptRecord(dek, context, {
          ...envelope,
          alg: 'A128CBC' as 'A256GCM',
        }),
      ).toThrow('Unsupported');
      expect(() =>
        decryptRecord(dek, context, {
          ...envelope,
          iv: toBase64(randomBytes(16)),
        }),
      ).toThrow('Malformed');
    });
  });

  it('refuses a data key that is not 32 bytes', () => {
    expect(() => encryptRecord(new Uint8Array(16), context, row)).toThrow(
      '32 bytes',
    );
    expect(() =>
      decryptRecord(
        new Uint8Array(33),
        context,
        encryptRecord(dek, context, row),
      ),
    ).toThrow('32 bytes');
  });
});

describe('blobs (receipt images)', () => {
  const where = { uid: 'uid-1', kind: 'receipt', id: 'r-1' };
  const image = randomBytes(300_000);

  it('round-trips and adds only the iv and tag', () => {
    const blob = encryptBlob(dek, where, image);
    expect(blob.length).toBe(image.length + 12 + 16);
    expect(Buffer.from(decryptBlob(dek, where, blob)).equals(image)).toBe(true);
  });

  it('is bound to its owner, kind and id, and detects tampering', () => {
    const blob = encryptBlob(dek, where, image);
    expect(() => decryptBlob(dek, { ...where, id: 'r-2' }, blob)).toThrow();
    expect(() => decryptBlob(dek, { ...where, uid: 'uid-2' }, blob)).toThrow();
    expect(() =>
      decryptBlob(dek, { ...where, kind: 'avatar' }, blob),
    ).toThrow();
    const altered = blob.slice();
    altered[5000] ^= 1;
    expect(() => decryptBlob(dek, where, altered)).toThrow();
    expect(() => decryptBlob(dek, where, blob.slice(0, 20))).toThrow(
      'Malformed',
    );
  });
});
