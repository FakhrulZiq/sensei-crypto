import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  fromBase64,
  fromBase64Url,
  toBase64,
  toBase64Url,
} from '../src/index.js';

describe('base64', () => {
  it('matches Node for every length from 0 to 70', () => {
    for (let length = 0; length <= 70; length++) {
      const bytes = randomBytes(length);
      expect(toBase64(bytes)).toBe(bytes.toString('base64'));
      expect(
        Buffer.from(fromBase64(bytes.toString('base64'))).equals(bytes),
      ).toBe(true);
      expect(toBase64Url(bytes)).toBe(bytes.toString('base64url'));
      expect(
        Buffer.from(fromBase64Url(bytes.toString('base64url'))).equals(bytes),
      ).toBe(true);
    }
  });

  it.each([
    ['missing padding', 'QUJD='],
    ['a character outside the alphabet', 'QU!D'],
    ['whitespace', 'QUJD\n'],
    ['url-safe characters in standard base64', 'QU-_'],
    ['padding in the middle', 'QQ==QQ=='],
    ['three padding characters', 'Q==='],
  ])('rejects %s', (_label, text) => {
    expect(() => fromBase64(text)).toThrow('Invalid base64');
  });
});

import { fromUtf8, utf8 } from '../src/bytes.js';

describe('utf8', () => {
  const samples = [
    '',
    'a',
    'Nasi lemak',
    'café',
    'naïve — “quotes”',
    '日本語のテキスト',
    '🍛🇲🇾👨‍👩‍👧‍👦',
    'mixed ascii é 日 🍛 end',
    '\u0000\u007f\u0080߿ࠀ￿',
    'x'.repeat(100_000),
    '🍛'.repeat(5000),
  ];

  it('matches TextEncoder/TextDecoder for ordinary text', () => {
    for (const text of samples) {
      const bytes = utf8(text);
      expect(
        Buffer.from(bytes).equals(Buffer.from(new TextEncoder().encode(text))),
      ).toBe(true);
      expect(fromUtf8(bytes)).toBe(text);
    }
  });

  it('matches for random code points across the whole range', () => {
    for (let round = 0; round < 200; round++) {
      let text = '';
      for (let i = 0; i < 50; i++) {
        let cp = Math.floor(Math.random() * 0x110000);
        if (cp >= 0xd800 && cp <= 0xdfff) cp = 0x41;
        text += String.fromCodePoint(cp);
      }
      expect(fromUtf8(utf8(text))).toBe(text);
      expect(
        Buffer.from(utf8(text)).equals(
          Buffer.from(new TextEncoder().encode(text)),
        ),
      ).toBe(true);
    }
  });

  it('turns a lone surrogate into U+FFFD, like TextEncoder', () => {
    for (const text of ['\ud800', 'a\udc00b', '\ud83d']) {
      expect(
        Buffer.from(utf8(text)).equals(
          Buffer.from(new TextEncoder().encode(text)),
        ),
      ).toBe(true);
    }
  });

  it.each([
    ['a lone continuation byte', [0x80]],
    ['a truncated 2-byte sequence', [0xc3]],
    ['a truncated 4-byte sequence', [0xf0, 0x9f, 0x8d]],
    ['an overlong encoding of "/"', [0xc0, 0xaf]],
    ['an overlong 3-byte encoding', [0xe0, 0x80, 0x80]],
    ['an encoded surrogate', [0xed, 0xa0, 0x80]],
    ['a code point above U+10FFFF', [0xf4, 0x90, 0x80, 0x80]],
    ['a byte that is never valid', [0xff]],
    ['a bad continuation byte', [0xe2, 0x28, 0xa1]],
  ])('rejects %s', (_label, bytes) => {
    expect(() => fromUtf8(Uint8Array.from(bytes))).toThrow('Invalid UTF-8');
  });
});
