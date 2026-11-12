import { gcm } from '@noble/ciphers/aes.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { fromBase64, toBase64, utf8 } from './bytes.js';
import { defaultRandom, type RandomBytes } from './random.js';
import { assertKey } from './records.js';
import {
  IV_BYTES,
  KEY_BYTES,
  type ScryptParams,
  type WrappedDataKey,
} from './types.js';

/** Mirrors what the server accepts (SCRYPT_LIMITS in sensei-be). */
export const SCRYPT_LIMITS = {
  minN: 2 ** 15,
  maxN: 2 ** 20,
  r: 8,
  maxP: 4,
  minSalt: 16,
  maxSalt: 64,
} as const;
export const DEFAULT_SCRYPT = { N: 2 ** 17, r: 8, p: 1 } as const;

export const generateDataKey = (
  random: RandomBytes = defaultRandom,
): Uint8Array => random(KEY_BYTES);

/** Parameters come back from the server, so they are checked before use: no huge cost, no weak cost. */
export function assertScryptParams(kdf: ScryptParams): void {
  const salt = fromBase64(kdf.salt);
  const powerOfTwo = Number.isInteger(kdf.N) && (kdf.N & (kdf.N - 1)) === 0;
  if (
    kdf.name !== 'scrypt' ||
    !powerOfTwo ||
    kdf.N < SCRYPT_LIMITS.minN ||
    kdf.N > SCRYPT_LIMITS.maxN ||
    kdf.r !== SCRYPT_LIMITS.r ||
    !Number.isInteger(kdf.p) ||
    kdf.p < 1 ||
    kdf.p > SCRYPT_LIMITS.maxP ||
    salt.length < SCRYPT_LIMITS.minSalt ||
    salt.length > SCRYPT_LIMITS.maxSalt
  ) {
    throw new Error('Unacceptable key derivation parameters');
  }
}

/** NFKC, so the same passphrase typed on different platforms gives the same key. */
const passphraseBytes = (passphrase: string) =>
  utf8(passphrase.normalize('NFKC'));
const wrapAad = (kid: string) => utf8(`sensei-dek-wrap|v1|${kid}`);

async function deriveKek(
  passphrase: string,
  kdf: ScryptParams,
): Promise<Uint8Array> {
  assertScryptParams(kdf);
  return scryptAsync(passphraseBytes(passphrase), fromBase64(kdf.salt), {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    dkLen: KEY_BYTES,
    // allow N up to 2^20: 128 * N * r = 1 GiB would be rejected by the default cap
    maxmem: 128 * kdf.N * kdf.r + 128 * kdf.r * kdf.p + 1024 * 1024,
  });
}

/** Produces the exact body for `POST /keys/add`. The passphrase never leaves the device. */
export async function wrapDataKey(input: {
  dek: Uint8Array;
  kid: string;
  passphrase: string;
  params?: { N: number; r: number; p: number };
  random?: RandomBytes;
}): Promise<WrappedDataKey> {
  const random = input.random ?? defaultRandom;
  assertKey(input.dek);
  if (input.passphrase.length === 0) throw new Error('Passphrase is empty');

  const params = input.params ?? DEFAULT_SCRYPT;
  const kdf: ScryptParams = {
    name: 'scrypt',
    ...params,
    salt: toBase64(random(16)),
  };
  const kek = await deriveKek(input.passphrase, kdf);
  const iv = random(IV_BYTES);
  const ct = gcm(kek, iv, wrapAad(input.kid)).encrypt(input.dek);
  return { kid: input.kid, kdf, wrap: { iv: toBase64(iv), ct: toBase64(ct) } };
}

/** Throws when the passphrase is wrong (or the stored key was altered). */
export async function unwrapDataKey(
  stored: Pick<WrappedDataKey, 'kid' | 'kdf' | 'wrap'>,
  passphrase: string,
): Promise<Uint8Array> {
  const kek = await deriveKek(passphrase, stored.kdf);
  try {
    return gcm(kek, fromBase64(stored.wrap.iv), wrapAad(stored.kid)).decrypt(
      fromBase64(stored.wrap.ct),
    );
  } catch {
    throw new Error('Wrong passphrase');
  }
}
