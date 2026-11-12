import { gcm } from '@noble/ciphers/aes.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  fromBase64,
  fromBase64Url,
  isAllZero,
  toBase64,
  toBase64Url,
  utf8,
} from './bytes.js';
import { defaultRandom, type RandomBytes } from './random.js';
import { assertKey } from './records.js';
import { IV_BYTES, KEY_BYTES, type LinkApproval } from './types.js';

const SESSION_ID = /^[A-Za-z0-9_-]{22}$/;

/** Browser: a one-time key pair. Only the public half is shown (in the QR code). */
export function createLinkKeys(random: RandomBytes = defaultRandom) {
  const privateKey = random(32);
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

/** ECDH -> HKDF-SHA256 -> a key used once, bound to the session id. */
function linkKey(
  privateKey: Uint8Array,
  peerPublicKey: Uint8Array,
  sessionId: string,
): Uint8Array {
  if (!SESSION_ID.test(sessionId)) throw new Error('Invalid session id');
  if (peerPublicKey.length !== 32) throw new Error('Invalid public key');
  const secret = x25519.getSharedSecret(privateKey, peerPublicKey);
  if (isAllZero(secret)) throw new Error('Invalid public key');
  return hkdf(
    sha256,
    secret,
    new Uint8Array(0),
    utf8(`sensei-key-link:${sessionId}`),
    KEY_BYTES,
  );
}

/**
 * Phone: wraps the data key for the browser whose public key came from the QR
 * code. Produces the body for `POST /key-links/:id/approve`.
 */
export function approveLink(input: {
  sessionId: string;
  webPublicKey: Uint8Array;
  dek: Uint8Array;
  random?: RandomBytes;
}): LinkApproval {
  const random = input.random ?? defaultRandom;
  assertKey(input.dek);
  const phone = createLinkKeys(random);
  const key = linkKey(phone.privateKey, input.webPublicKey, input.sessionId);
  const iv = random(IV_BYTES);
  const ct = gcm(key, iv, utf8(input.sessionId)).encrypt(input.dek);
  return {
    phonePublicKey: toBase64(phone.publicKey),
    iv: toBase64(iv),
    ct: toBase64(ct),
  };
}

/** Browser: recovers the data key from the phone's approval. Throws if it was not made for this browser. */
export function openLinkApproval(input: {
  sessionId: string;
  webPrivateKey: Uint8Array;
  approval: LinkApproval;
}): Uint8Array {
  const key = linkKey(
    input.webPrivateKey,
    fromBase64(input.approval.phonePublicKey),
    input.sessionId,
  );
  try {
    return gcm(
      key,
      fromBase64(input.approval.iv),
      utf8(input.sessionId),
    ).decrypt(fromBase64(input.approval.ct));
  } catch {
    throw new Error('Link approval is not for this browser');
  }
}

/** What the browser shows as a QR code. The server never sees `k`. */
export function encodeLinkQr(input: {
  sessionId: string;
  webPublicKey: Uint8Array;
}): string {
  return `sensei://link?s=${input.sessionId}&k=${toBase64Url(input.webPublicKey)}`;
}

export function decodeLinkQr(text: string): {
  sessionId: string;
  webPublicKey: Uint8Array;
} {
  const match =
    /^sensei:\/\/link\?s=([A-Za-z0-9_-]{22})&k=([A-Za-z0-9_-]{43})$/.exec(
      text.trim(),
    );
  if (!match) throw new Error('Not a SenSei link code');
  const webPublicKey = fromBase64Url(match[2]);
  if (webPublicKey.length !== 32) throw new Error('Not a SenSei link code');
  return { sessionId: match[1], webPublicKey };
}
