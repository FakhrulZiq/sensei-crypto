import { scryptSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  assertScryptParams,
  fromBase64,
  generateDataKey,
  toBase64,
  unwrapDataKey,
  wrapDataKey,
} from '../src/index.js';
import {
  counting,
  nodeGcmDecrypt,
  nodeGcmEncrypt,
  scripted,
} from './helpers.js';

const fast = { N: 2 ** 15, r: 8, p: 1 };
const dek = counting(32, 7);

describe('passphrase wrapping', () => {
  it('round-trips, and a different device with the same passphrase gets the same key', async () => {
    const wrapped = await wrapDataKey({
      dek,
      kid: 'k_test0001',
      passphrase: 'correct horse battery staple',
      params: fast,
    });
    expect(
      await unwrapDataKey(wrapped, 'correct horse battery staple'),
    ).toEqual(dek);
  });

  it('produces exactly the body POST /keys/add accepts', async () => {
    const body = await wrapDataKey({
      dek,
      kid: 'k_test0001',
      passphrase: 'pw-pw-pw-pw',
      params: fast,
    });
    expect(Object.keys(body).sort()).toEqual(['kdf', 'kid', 'wrap']);
    expect(body.kdf).toMatchObject({ name: 'scrypt', N: 2 ** 15, r: 8, p: 1 });
    expect(fromBase64(body.kdf.salt)).toHaveLength(16);
    expect(fromBase64(body.wrap.iv)).toHaveLength(12);
    expect(fromBase64(body.wrap.ct)).toHaveLength(48);
    expect(JSON.stringify(body)).not.toContain('pw-pw-pw-pw');
  });

  it('uses the standard algorithms: Node scrypt + AES-256-GCM interoperate in both directions', async () => {
    const salt = counting(16, 200);
    const iv = counting(12, 90);
    const wrapped = await wrapDataKey({
      dek,
      kid: 'k_test0001',
      passphrase: 'interop passphrase',
      params: fast,
      random: scripted(salt, iv),
    });

    const kek = scryptSync('interop passphrase', salt, 32, {
      ...fast,
      maxmem: 64 * 1024 * 1024,
    });
    expect(
      nodeGcmDecrypt(
        kek,
        iv,
        'sensei-dek-wrap|v1|k_test0001',
        fromBase64(wrapped.wrap.ct),
      ).equals(Buffer.from(dek)),
    ).toBe(true);

    const nodeIv = counting(12, 10);
    const nodeCt = nodeGcmEncrypt(
      kek,
      nodeIv,
      'sensei-dek-wrap|v1|k_test0001',
      dek,
    );
    expect(
      await unwrapDataKey(
        {
          kid: 'k_test0001',
          kdf: wrapped.kdf,
          wrap: { iv: toBase64(nodeIv), ct: toBase64(nodeCt) },
        },
        'interop passphrase',
      ),
    ).toEqual(dek);
  });

  it('refuses a wrong passphrase, a different key id, and an altered wrap', async () => {
    const wrapped = await wrapDataKey({
      dek,
      kid: 'k_test0001',
      passphrase: 'right',
      params: fast,
    });
    await expect(unwrapDataKey(wrapped, 'wrong')).rejects.toThrow(
      'Wrong passphrase',
    );
    await expect(unwrapDataKey(wrapped, 'right ')).rejects.toThrow(
      'Wrong passphrase',
    );
    await expect(
      unwrapDataKey({ ...wrapped, kid: 'k_other001' }, 'right'),
    ).rejects.toThrow('Wrong passphrase');
    const ct = fromBase64(wrapped.wrap.ct);
    ct[3] ^= 1;
    await expect(
      unwrapDataKey(
        { ...wrapped, wrap: { ...wrapped.wrap, ct: toBase64(ct) } },
        'right',
      ),
    ).rejects.toThrow();
  });

  it('treats visually identical passphrases as the same (Unicode NFKC)', async () => {
    const composed = 'café ①';
    const decomposed = 'café 1';
    const wrapped = await wrapDataKey({
      dek,
      kid: 'k_test0001',
      passphrase: composed,
      params: fast,
    });
    expect(await unwrapDataKey(wrapped, decomposed)).toEqual(dek);
  });

  it('refuses an empty passphrase and a wrong-sized key', async () => {
    await expect(
      wrapDataKey({ dek, kid: 'k_test0001', passphrase: '', params: fast }),
    ).rejects.toThrow('empty');
    await expect(
      wrapDataKey({
        dek: new Uint8Array(31),
        kid: 'k_test0001',
        passphrase: 'x',
        params: fast,
      }),
    ).rejects.toThrow('32 bytes');
  });

  it('generates a different key and salt every time', async () => {
    expect(generateDataKey()).not.toEqual(generateDataKey());
    const a = await wrapDataKey({
      dek,
      kid: 'k_test0001',
      passphrase: 'x',
      params: fast,
    });
    const b = await wrapDataKey({
      dek,
      kid: 'k_test0001',
      passphrase: 'x',
      params: fast,
    });
    expect(a.kdf.salt).not.toBe(b.kdf.salt);
    expect(a.wrap.ct).not.toBe(b.wrap.ct);
  });

  describe('does not trust parameters that come back from the server', () => {
    const good = {
      name: 'scrypt' as const,
      N: 2 ** 17,
      r: 8,
      p: 1,
      salt: toBase64(counting(16)),
    };

    it('accepts the defaults and the documented range', () => {
      expect(() => assertScryptParams(good)).not.toThrow();
      expect(() => assertScryptParams({ ...good, N: 2 ** 15 })).not.toThrow();
      expect(() =>
        assertScryptParams({ ...good, N: 2 ** 20, p: 4 }),
      ).not.toThrow();
    });

    it.each([
      ['a cost so low it is trivially brute-forced', { N: 2 ** 10 }],
      ['a cost that would freeze or crash the device', { N: 2 ** 30 }],
      ['a cost above the supported maximum', { N: 2 ** 21 }],
      ['a cost that is not a power of two', { N: 100_000 }],
      ['r other than 8', { r: 1 }],
      ['p of zero', { p: 0 }],
      ['p above 4', { p: 5 }],
      ['a short salt', { salt: toBase64(counting(8)) }],
      ['another KDF', { name: 'pbkdf2' as 'scrypt' }],
    ])('rejects %s', async (_label, override) => {
      const kdf = { ...good, ...override };
      expect(() => assertScryptParams(kdf)).toThrow('Unacceptable');
      await expect(
        unwrapDataKey(
          {
            kid: 'k_test0001',
            kdf,
            wrap: { iv: toBase64(counting(12)), ct: toBase64(counting(48)) },
          },
          'x',
        ),
      ).rejects.toThrow('Unacceptable');
    });
  });
});
