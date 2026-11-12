export const KEY_BYTES = 32;
export const IV_BYTES = 12;
export const TAG_BYTES = 16;

/** The ciphertext of one record, in the shape the server stores (base64 strings). */
export interface Envelope {
  v: 1;
  alg: 'A256GCM';
  kid: string;
  iv: string;
  ct: string;
}

/** Where a record lives. Bound into the ciphertext so the server cannot move or swap records. */
export interface RecordContext {
  uid: string;
  table: string;
  recordId: string;
  kid: string;
}

export interface ScryptParams {
  name: 'scrypt';
  N: number;
  r: number;
  p: number;
  /** base64 */
  salt: string;
}

/** The body of `POST /keys/add` (and, without `kid`, `PUT /keys/:kid`). */
export interface WrappedDataKey {
  kid: string;
  kdf: ScryptParams;
  wrap: { iv: string; ct: string };
}

/** The body of `POST /key-links/:id/approve`. */
export interface LinkApproval {
  phonePublicKey: string;
  iv: string;
  ct: string;
}
