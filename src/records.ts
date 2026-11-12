import { gcm } from '@noble/ciphers/aes.js';
import { fromBase64, fromUtf8, toBase64, utf8 } from './bytes.js';
import { defaultRandom, type RandomBytes } from './random.js';
import {
  IV_BYTES,
  KEY_BYTES,
  TAG_BYTES,
  type Envelope,
  type RecordContext,
} from './types.js';

export function assertKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) {
    throw new Error('Data key must be 32 bytes');
  }
}

/** Binds the ciphertext to its owner and place. Format version 1. */
export function recordAad(
  context: Pick<RecordContext, 'uid' | 'table' | 'recordId'>,
): Uint8Array {
  return utf8(`${context.uid}|${context.table}|${context.recordId}|v1`);
}

/** Encrypts one row (any JSON value) into the envelope the server stores. */
export function encryptRecord(
  dek: Uint8Array,
  context: RecordContext,
  value: unknown,
  random: RandomBytes = defaultRandom,
): Envelope {
  assertKey(dek);
  const iv = random(IV_BYTES);
  const ct = gcm(dek, iv, recordAad(context)).encrypt(
    utf8(JSON.stringify(value)),
  );
  return {
    v: 1,
    alg: 'A256GCM',
    kid: context.kid,
    iv: toBase64(iv),
    ct: toBase64(ct),
  };
}

/** Throws if the data was altered, belongs to another record or user, or the key is wrong. */
export function decryptRecord<T = unknown>(
  dek: Uint8Array,
  context: Pick<RecordContext, 'uid' | 'table' | 'recordId'>,
  envelope: Envelope,
): T {
  assertKey(dek);
  if (envelope.v !== 1 || envelope.alg !== 'A256GCM') {
    throw new Error('Unsupported envelope');
  }
  const iv = fromBase64(envelope.iv);
  const ct = fromBase64(envelope.ct);
  if (iv.length !== IV_BYTES || ct.length < TAG_BYTES) {
    throw new Error('Malformed envelope');
  }
  const plaintext = gcm(dek, iv, recordAad(context)).decrypt(ct);
  return JSON.parse(fromUtf8(plaintext)) as T;
}

/** Binary data such as receipt images: `iv || ciphertext || tag`. */
export function encryptBlob(
  dek: Uint8Array,
  context: { uid: string; kind: string; id: string },
  bytes: Uint8Array,
  random: RandomBytes = defaultRandom,
): Uint8Array {
  assertKey(dek);
  const iv = random(IV_BYTES);
  const ct = gcm(dek, iv, blobAad(context)).encrypt(bytes);
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return out;
}

export function decryptBlob(
  dek: Uint8Array,
  context: { uid: string; kind: string; id: string },
  blob: Uint8Array,
): Uint8Array {
  assertKey(dek);
  if (blob.length < IV_BYTES + TAG_BYTES) throw new Error('Malformed blob');
  return gcm(dek, blob.slice(0, IV_BYTES), blobAad(context)).decrypt(
    blob.slice(IV_BYTES),
  );
}

const blobAad = (context: { uid: string; kind: string; id: string }) =>
  utf8(`${context.uid}|blob:${context.kind}|${context.id}|v1`);
