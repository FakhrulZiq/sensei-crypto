import { createDecipheriv, createCipheriv } from 'node:crypto';
import type { RandomBytes } from '../src/index.js';

/** Hands out the given byte strings in order, so output is reproducible. */
export function scripted(...chunks: Uint8Array[]): RandomBytes {
  let next = 0;
  return (length) => {
    const chunk = chunks[next++];
    if (!chunk || chunk.length !== length) {
      throw new Error(
        `scripted random: call ${next} wanted ${length} bytes, had ${chunk?.length}`,
      );
    }
    return chunk;
  };
}

export const counting = (length: number, start = 0) =>
  Uint8Array.from({ length }, (_, i) => (start + i) & 255);

/** Independent AES-256-GCM using Node, ciphertext || tag. */
export function nodeGcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  aad: string,
  plaintext: Uint8Array,
) {
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  return Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
}

export function nodeGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  aad: string,
  ctWithTag: Uint8Array,
) {
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(ctWithTag.slice(ctWithTag.length - 16)));
  return Buffer.concat([
    decipher.update(ctWithTag.slice(0, ctWithTag.length - 16)),
    decipher.final(),
  ]);
}
