import { sha256 } from '@noble/hashes/sha2.js';
import { utf8 } from './bytes.js';

/** Lower-case hex SHA-256 of a UTF-8 string. Same result on every platform. */
export function sha256Hex(text: string): string {
  return Array.from(sha256(utf8(text)), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}

/** Lower-case hex SHA-256 of bytes (to check a downloaded file against the catalog manifest). */
export function sha256HexOfBytes(bytes: Uint8Array): string {
  return Array.from(sha256(bytes), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}
