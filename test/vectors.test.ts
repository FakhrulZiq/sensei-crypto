import { scryptSync } from 'node:crypto';
import { x25519 } from '@noble/curves/ed25519.js';
import { describe, expect, it } from 'vitest';
import {
  approveLink,
  decryptBlob,
  decryptRecord,
  encryptBlob,
  encryptRecord,
  fromBase64,
  openLinkApproval,
  toBase64,
  unwrapDataKey,
  wrapDataKey,
} from '../src/index.js';
import { counting, nodeGcmDecrypt, scripted } from './helpers.js';

/**
 * Frozen outputs for fixed inputs. If one of these changes, the format changed:
 * every phone and browser already holding data would stop being able to read it.
 * Change a vector only together with a new format version.
 */
const dek = counting(32);

const RECORD = {
  v: 1,
  alg: 'A256GCM',
  kid: 'k_test0001',
  iv: 'ZGVmZ2hpamtsbW5v',
  ct: 'Mzm3AlvTdOpGT27K9kcLkC23aH7UH5Ycheudes6TiWr6hjSlbii5SpyAER+RJ6eucHnl80V1Sr6sU/ftf6E5T9sIEw==',
} as const;

const WRAP = {
  kid: 'k_test0001',
  kdf: {
    name: 'scrypt',
    N: 32768,
    r: 8,
    p: 1,
    salt: 'yMnKy8zNzs/Q0dLT1NXW1w==',
  },
  wrap: {
    iv: 'WltcXV5fYGFiY2Rl',
    ct: 'Ze+sGEpKDpAyTC5RdiNWi4D5jwJZX03zIFMf10hbgDZg9+t1u2S+ry8vI7QJHDtQ',
  },
} as const;

const LINK = {
  sessionId: 'AAAAAAAAAAAAAAAAAAAAAA',
  webPrivateKey: counting(32, 1),
  webPublicKey: 'B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=',
  approval: {
    phonePublicKey: '4Fsa4yICSDgJX/3v2GVGjdt3sUst0nUXXqCrQpT6bXo=',
    iv: 'PD0+P0BBQkNERUZH',
    ct: 'iOt7DWycdwV2EpL0Jp2CZg/vGbSqBpqreMGPoclZxd/NGZsAl4rq47lCG07oChsq',
  },
};

const BLOB = 'RkdISUpLTE1OT1BRy/sYbEl6pyfNxZeczq1f46TWFZcug1HrG/aXXYSo3i5KaUjK';

describe('frozen test vectors', () => {
  it('record envelope', () => {
    const context = {
      uid: 'uid-1',
      table: 'transactions',
      recordId: 'tx-1',
      kid: 'k_test0001',
    };
    const value = { id: 'tx-1', amount_sen: 1250, note: 'Nasi lemak' };
    expect(
      encryptRecord(dek, context, value, scripted(counting(12, 100))),
    ).toEqual(RECORD);
    expect(decryptRecord(dek, context, RECORD)).toEqual(value);

    // verified independently of this library
    const plaintext = nodeGcmDecrypt(
      dek,
      fromBase64(RECORD.iv),
      'uid-1|transactions|tx-1|v1',
      fromBase64(RECORD.ct),
    );
    expect(plaintext.toString()).toBe(
      '{"id":"tx-1","amount_sen":1250,"note":"Nasi lemak"}',
    );
  });

  it('passphrase-wrapped data key', async () => {
    const wrapped = await wrapDataKey({
      dek,
      kid: 'k_test0001',
      passphrase: 'correct horse battery staple',
      params: { N: 2 ** 15, r: 8, p: 1 },
      random: scripted(counting(16, 200), counting(12, 90)),
    });
    expect(wrapped).toEqual(WRAP);
    expect(await unwrapDataKey(WRAP, 'correct horse battery staple')).toEqual(
      dek,
    );

    const kek = scryptSync(
      'correct horse battery staple',
      fromBase64(WRAP.kdf.salt),
      32,
      {
        N: 2 ** 15,
        r: 8,
        p: 1,
        maxmem: 64 * 1024 * 1024,
      },
    );
    const opened = nodeGcmDecrypt(
      kek,
      fromBase64(WRAP.wrap.iv),
      'sensei-dek-wrap|v1|k_test0001',
      fromBase64(WRAP.wrap.ct),
    );
    expect(opened.equals(Buffer.from(dek))).toBe(true);
  });

  it('browser link approval', () => {
    expect(toBase64(x25519.getPublicKey(LINK.webPrivateKey))).toBe(
      LINK.webPublicKey,
    );
    const approval = approveLink({
      sessionId: LINK.sessionId,
      webPublicKey: fromBase64(LINK.webPublicKey),
      dek,
      random: scripted(counting(32, 50), counting(12, 60)),
    });
    expect(approval).toEqual(LINK.approval);
    expect(
      openLinkApproval({
        sessionId: LINK.sessionId,
        webPrivateKey: LINK.webPrivateKey,
        approval: LINK.approval,
      }),
    ).toEqual(dek);
  });

  it('encrypted blob', () => {
    const where = { uid: 'uid-1', kind: 'receipt', id: 'r-1' };
    expect(
      toBase64(
        encryptBlob(dek, where, counting(20), scripted(counting(12, 70))),
      ),
    ).toBe(BLOB);
    expect(decryptBlob(dek, where, fromBase64(BLOB))).toEqual(counting(20));
  });
});
