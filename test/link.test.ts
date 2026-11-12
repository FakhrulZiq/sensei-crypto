import {
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
} from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  approveLink,
  createLinkKeys,
  decodeLinkQr,
  encodeLinkQr,
  fromBase64,
  generateDataKey,
  openLinkApproval,
  toBase64,
} from '../src/index.js';
import { counting, nodeGcmDecrypt, nodeGcmEncrypt } from './helpers.js';

const SESSION = 'AAAAAAAAAAAAAAAAAAAAAA';
const OTHER_SESSION = 'BBBBBBBBBBBBBBBBBBBBBB';
const dek = counting(32, 3);

// Node's X25519 keys <-> raw bytes (RFC 8410 prefixes)
const SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const nodePublic = (raw: Uint8Array) =>
  createPublicKey({
    key: Buffer.concat([SPKI, raw]),
    format: 'der',
    type: 'spki',
  });
const nodePrivate = (raw: Uint8Array) =>
  createPrivateKey({
    key: Buffer.concat([PKCS8, raw]),
    format: 'der',
    type: 'pkcs8',
  });
const nodeLinkKey = (priv: Uint8Array, pub: Uint8Array, session: string) =>
  Buffer.from(
    hkdfSync(
      'sha256',
      diffieHellman({
        privateKey: nodePrivate(priv),
        publicKey: nodePublic(pub),
      }),
      Buffer.alloc(0),
      `sensei-key-link:${session}`,
      32,
    ),
  );

describe('browser linking', () => {
  it('hands the data key from phone to browser', () => {
    const web = createLinkKeys();
    const approval = approveLink({
      sessionId: SESSION,
      webPublicKey: web.publicKey,
      dek,
    });
    expect(
      openLinkApproval({
        sessionId: SESSION,
        webPrivateKey: web.privateKey,
        approval,
      }),
    ).toEqual(dek);
  });

  it('produces exactly the body POST /key-links/:id/approve accepts', () => {
    const approval = approveLink({
      sessionId: SESSION,
      webPublicKey: createLinkKeys().publicKey,
      dek,
    });
    expect(Object.keys(approval).sort()).toEqual([
      'ct',
      'iv',
      'phonePublicKey',
    ]);
    expect(fromBase64(approval.phonePublicKey)).toHaveLength(32);
    expect(fromBase64(approval.iv)).toHaveLength(12);
    expect(fromBase64(approval.ct)).toHaveLength(48);
    expect(JSON.stringify(approval)).not.toContain(toBase64(dek));
  });

  it('interoperates with Node when the phone side is this library', () => {
    const web = generateKeyPairSync('x25519');
    const rawPriv = (
      web.privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer
    ).subarray(PKCS8.length);
    const rawPub = (
      web.publicKey.export({ format: 'der', type: 'spki' }) as Buffer
    ).subarray(SPKI.length);

    const approval = approveLink({
      sessionId: SESSION,
      webPublicKey: rawPub,
      dek,
    });
    const key = nodeLinkKey(
      rawPriv,
      fromBase64(approval.phonePublicKey),
      SESSION,
    );
    expect(
      nodeGcmDecrypt(
        key,
        fromBase64(approval.iv),
        SESSION,
        fromBase64(approval.ct),
      ).equals(Buffer.from(dek)),
    ).toBe(true);
  });

  it('interoperates with Node when the phone side is Node (the protocol the backend tests use)', () => {
    const web = createLinkKeys();
    const phone = generateKeyPairSync('x25519');
    const phonePriv = (
      phone.privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer
    ).subarray(PKCS8.length);
    const phonePub = (
      phone.publicKey.export({ format: 'der', type: 'spki' }) as Buffer
    ).subarray(SPKI.length);

    const key = nodeLinkKey(phonePriv, web.publicKey, SESSION);
    const iv = counting(12, 40);
    const ct = nodeGcmEncrypt(key, iv, SESSION, dek);
    const opened = openLinkApproval({
      sessionId: SESSION,
      webPrivateKey: web.privateKey,
      approval: {
        phonePublicKey: toBase64(phonePub),
        iv: toBase64(iv),
        ct: toBase64(ct),
      },
    });
    expect(opened).toEqual(dek);
  });

  it('cannot be opened by another browser, or under another session', () => {
    const web = createLinkKeys();
    const approval = approveLink({
      sessionId: SESSION,
      webPublicKey: web.publicKey,
      dek,
    });
    expect(() =>
      openLinkApproval({
        sessionId: SESSION,
        webPrivateKey: createLinkKeys().privateKey,
        approval,
      }),
    ).toThrow('not for this browser');
    expect(() =>
      openLinkApproval({
        sessionId: OTHER_SESSION,
        webPrivateKey: web.privateKey,
        approval,
      }),
    ).toThrow('not for this browser');
  });

  it('detects an altered approval', () => {
    const web = createLinkKeys();
    const approval = approveLink({
      sessionId: SESSION,
      webPublicKey: web.publicKey,
      dek,
    });
    const ct = fromBase64(approval.ct);
    ct[0] ^= 1;
    expect(() =>
      openLinkApproval({
        sessionId: SESSION,
        webPrivateKey: web.privateKey,
        approval: { ...approval, ct: toBase64(ct) },
      }),
    ).toThrow();
  });

  it('uses a one-time key every approval, so approvals of the same key differ', () => {
    const web = createLinkKeys();
    const a = approveLink({
      sessionId: SESSION,
      webPublicKey: web.publicKey,
      dek,
    });
    const b = approveLink({
      sessionId: SESSION,
      webPublicKey: web.publicKey,
      dek,
    });
    expect(a.phonePublicKey).not.toBe(b.phonePublicKey);
    expect(a.ct).not.toBe(b.ct);
  });

  it('refuses a low-order public key, which would make the shared secret all zeros', () => {
    expect(() =>
      approveLink({
        sessionId: SESSION,
        webPublicKey: new Uint8Array(32),
        dek,
      }),
    ).toThrow();
    const lowOrderOne = new Uint8Array(32);
    lowOrderOne[0] = 1;
    expect(() =>
      approveLink({ sessionId: SESSION, webPublicKey: lowOrderOne, dek }),
    ).toThrow();
  });

  it('refuses malformed sessions, keys and data keys', () => {
    const web = createLinkKeys();
    expect(() =>
      approveLink({ sessionId: 'short', webPublicKey: web.publicKey, dek }),
    ).toThrow('session id');
    expect(() =>
      approveLink({
        sessionId: SESSION,
        webPublicKey: new Uint8Array(31),
        dek,
      }),
    ).toThrow('public key');
    expect(() =>
      approveLink({
        sessionId: SESSION,
        webPublicKey: web.publicKey,
        dek: generateDataKey().slice(0, 16),
      }),
    ).toThrow('32 bytes');
  });
});

describe('QR code payload', () => {
  it('round-trips and carries the public key, never a private one', () => {
    const web = createLinkKeys();
    const text = encodeLinkQr({
      sessionId: SESSION,
      webPublicKey: web.publicKey,
    });
    expect(text).toMatch(
      /^sensei:\/\/link\?s=[A-Za-z0-9_-]{22}&k=[A-Za-z0-9_-]{43}$/,
    );
    expect(text).not.toContain(toBase64(web.privateKey));
    const decoded = decodeLinkQr(text);
    expect(decoded.sessionId).toBe(SESSION);
    expect(decoded.webPublicKey).toEqual(web.publicKey);
    expect(decodeLinkQr(`  ${text}\n`).sessionId).toBe(SESSION);
  });

  it.each([
    [
      'another scheme',
      'https://evil.example/link?s=AAAAAAAAAAAAAAAAAAAAAA&k=' + 'A'.repeat(43),
    ],
    [
      'extra parameters',
      `sensei://link?s=${SESSION}&k=${'A'.repeat(43)}&redirect=x`,
    ],
    ['a short key', `sensei://link?s=${SESSION}&k=${'A'.repeat(20)}`],
    ['a short session', `sensei://link?s=abc&k=${'A'.repeat(43)}`],
    ['plain text', 'hello'],
    ['empty', ''],
  ])('rejects %s', (_label, text) => {
    expect(() => decodeLinkQr(text)).toThrow('Not a SenSei link code');
  });
});
