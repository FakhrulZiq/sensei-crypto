export type RandomBytes = (length: number) => Uint8Array;

/**
 * Browsers and Node have `crypto.getRandomValues`. React Native does not by
 * default: pass `(n) => ExpoCrypto.getRandomBytes(n)` instead.
 */
export const defaultRandom: RandomBytes = (length) => {
  const source = (globalThis as { crypto?: Crypto }).crypto;
  if (!source?.getRandomValues) {
    throw new Error('No secure random source: pass a `random` function');
  }
  return source.getRandomValues(new Uint8Array(length));
};
