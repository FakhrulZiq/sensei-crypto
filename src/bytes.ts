const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = new Map([...B64].map((char, index) => [char, index]));

/** Standard base64 with padding. Pure JS: React Native has no Buffer. */
export function toBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n =
      (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    out += i + 1 < bytes.length ? B64[(n >> 6) & 63] : '=';
    out += i + 2 < bytes.length ? B64[n & 63] : '=';
  }
  return out;
}

/** Strict: rejects anything that is not canonical padded base64. */
export function fromBase64(text: string): Uint8Array {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw new Error('Invalid base64');
  }
  const padding = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((text.length / 4) * 3 - padding);
  let o = 0;
  for (let i = 0; i < text.length; i += 4) {
    const a = B64_LOOKUP.get(text[i]) ?? 0;
    const b = B64_LOOKUP.get(text[i + 1]) ?? 0;
    const c = B64_LOOKUP.get(text[i + 2]) ?? 0;
    const d = B64_LOOKUP.get(text[i + 3]) ?? 0;
    const n = (a << 18) | (b << 12) | (c << 6) | d;
    if (o < out.length) out[o++] = (n >> 16) & 255;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function fromBase64Url(text: string): Uint8Array {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  return fromBase64(padded + '='.repeat((4 - (padded.length % 4)) % 4));
}

/**
 * Pure-JS UTF-8, so nothing depends on `TextEncoder`/`TextDecoder` options that
 * some JavaScript engines (Hermes) do not fully support. Lone surrogates become U+FFFD,
 * like `TextEncoder`.
 */
export function utf8(text: string): Uint8Array {
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    let cp = text.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        cp = 0x10000 + ((cp - 0xd800) << 10) + (next - 0xdc00);
        i++;
      } else {
        cp = 0xfffd;
      }
    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
      cp = 0xfffd;
    }
    if (cp < 0x80) bytes.push(cp);
    else if (cp < 0x800) bytes.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
    else if (cp < 0x10000)
      bytes.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    else
      bytes.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 63),
        0x80 | ((cp >> 6) & 63),
        0x80 | (cp & 63),
      );
  }
  return Uint8Array.from(bytes);
}

/** Strict: throws on overlong forms, surrogates, out-of-range values and truncated sequences. */
export function fromUtf8(bytes: Uint8Array): string {
  let out = '';
  let chunk: number[] = [];
  const flush = () => {
    out += String.fromCodePoint(...chunk);
    chunk = [];
  };
  for (let i = 0; i < bytes.length;) {
    const b = bytes[i];
    let cp: number;
    let extra: number;
    let min: number;
    if (b < 0x80) [cp, extra, min] = [b, 0, 0];
    else if (b >= 0xc2 && b <= 0xdf) [cp, extra, min] = [b & 0x1f, 1, 0x80];
    else if (b >= 0xe0 && b <= 0xef) [cp, extra, min] = [b & 0x0f, 2, 0x800];
    else if (b >= 0xf0 && b <= 0xf4) [cp, extra, min] = [b & 0x07, 3, 0x10000];
    else throw new Error('Invalid UTF-8');
    for (let k = 1; k <= extra; k++) {
      const c = bytes[i + k];
      if (c === undefined || (c & 0xc0) !== 0x80)
        throw new Error('Invalid UTF-8');
      cp = (cp << 6) | (c & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
      throw new Error('Invalid UTF-8');
    chunk.push(cp);
    if (chunk.length >= 4096) flush();
    i += extra + 1;
  }
  if (chunk.length) flush();
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export const isAllZero = (bytes: Uint8Array): boolean =>
  bytes.every((byte) => byte === 0);
