/**
 * Cryptographic utilities for the Citrate JavaScript SDK.
 *
 * RM-G2.6 (audit SUP-04 + SUP-05):
 *   - `crypto-js` and `elliptic` are gone from the dependency graph.
 *     Both had unpatched advisories at the bounds the lockfile
 *     pinned, and `elliptic` wasn't even imported anywhere in src/.
 *   - Hashing, AES-GCM, PBKDF2, and HMAC now route exclusively
 *     through the Web Crypto API exposed by `globalThis.crypto`,
 *     which is available in Node.js >= 16.0 and every modern
 *     browser. The pre-RM-G2.6 `require('crypto')` and CryptoJS
 *     fallback paths are deleted — they only existed for IE11 /
 *     Node < 16, neither of which the SDK supports.
 */

/// RM-G.7 — default PBKDF2-HMAC-SHA256 iteration count. The previous default
/// (10,000) was far below current guidance; OWASP recommends >= 600,000 for
/// PBKDF2-SHA256. Callers that need a different work factor pass it explicitly.
export const PBKDF2_DEFAULT_ITERATIONS = 600_000;

function ensureWebCrypto(): SubtleCrypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || !c.subtle) {
    throw new Error(
      'CryptoManager requires Web Crypto API. Node 16+ exposes it via globalThis.crypto.',
    );
  }
  return c.subtle;
}

export class CryptoManager {
  /**
   * Hash data using SHA-256. Returns lowercase hex.
   */
  async hashData(data: Uint8Array): Promise<string> {
    const subtle = ensureWebCrypto();
    const buf = await subtle.digest('SHA-256', data as BufferSource);
    return bytesToHex(new Uint8Array(buf));
  }

  /**
   * Generate cryptographically random bytes.
   */
  generateRandomBytes(length: number): Uint8Array {
    const c = (globalThis as { crypto?: Crypto }).crypto;
    if (!c || typeof c.getRandomValues !== 'function') {
      throw new Error('CryptoManager requires Web Crypto getRandomValues');
    }
    const out = new Uint8Array(length);
    c.getRandomValues(out);
    return out;
  }

  /**
   * Encrypt with AES-256-GCM. Returns the ciphertext + nonce + the
   * 16-byte auth tag separately so callers can persist each
   * independently. The auth tag is the last 16 bytes of the Web
   * Crypto output by spec — we slice it off here.
   */
  async encryptAES(
    data: Uint8Array,
    key: Uint8Array,
  ): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array; authTag: Uint8Array }> {
    const subtle = ensureWebCrypto();
    const nonce = this.generateRandomBytes(12);
    const cryptoKey = await subtle.importKey(
      'raw',
      key as BufferSource,
      { name: 'AES-GCM' },
      false,
      ['encrypt'],
    );
    const buf = await subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource },
      cryptoKey,
      data as BufferSource,
    );
    const out = new Uint8Array(buf);
    const ciphertext = out.slice(0, out.length - 16);
    const authTag = out.slice(out.length - 16);
    return { ciphertext, nonce, authTag };
  }

  /**
   * Decrypt AES-256-GCM ciphertext. The auth tag is appended to the
   * ciphertext before handing it to Web Crypto, mirroring the layout
   * `encryptAES` produces.
   */
  async decryptAES(
    ciphertext: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    authTag: Uint8Array,
  ): Promise<Uint8Array> {
    const subtle = ensureWebCrypto();
    const cryptoKey = await subtle.importKey(
      'raw',
      key as BufferSource,
      { name: 'AES-GCM' },
      false,
      ['decrypt'],
    );
    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext);
    combined.set(authTag, ciphertext.length);
    const buf = await subtle.decrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource },
      cryptoKey,
      combined as BufferSource,
    );
    return new Uint8Array(buf);
  }

  /**
   * Derive a 32-byte key from password + salt using PBKDF2-SHA256.
   * Async — callers that previously called the sync stub must await.
   */
  async deriveKey(
    password: string,
    salt: Uint8Array,
    iterations = PBKDF2_DEFAULT_ITERATIONS,
  ): Promise<Uint8Array> {
    const subtle = ensureWebCrypto();
    const passwordBytes = new TextEncoder().encode(password);
    const baseKey = await subtle.importKey(
      'raw',
      passwordBytes as BufferSource,
      { name: 'PBKDF2' },
      false,
      ['deriveBits'],
    );
    const bits = await subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt as BufferSource,
        iterations,
        hash: 'SHA-256',
      },
      baseKey,
      32 * 8,
    );
    return new Uint8Array(bits);
  }

  /**
   * HKDF-SHA256 (RFC 5869) — extract-and-expand key derivation. Used to derive
   * the ECDH key-encryption key from the raw shared secret with a per-message
   * salt and a domain-separating `info` that binds both endpoint public keys
   * (SJS-B-009). Returns `length` bytes (default 32).
   *
   * This replaces the prior bare `SHA-256(x-coordinate)`, which had no salt, no
   * domain separation, and — via a slice bug — dropped a byte of the shared
   * secret. HKDF here matches the citrate-sdk-python V2 envelope so the two SDKs
   * can interoperate when fed identical (ikm, salt, info).
   */
  async hkdfSha256(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length = 32,
  ): Promise<Uint8Array> {
    const subtle = ensureWebCrypto();
    const baseKey = await subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, [
      'deriveBits',
    ]);
    const bits = await subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: info as BufferSource },
      baseKey,
      length * 8,
    );
    return new Uint8Array(bits);
  }

  /**
   * Derive a 32-byte key from raw password *bytes* + salt using PBKDF2-SHA256.
   *
   * SJS-B-011: the string-based `deriveKey` forces callers to build the password
   * as a template literal — `` `…:${wallet.privateKey}` `` — which interns a
   * fresh, immutable, unwipeable copy of the raw private key on every wrap/unwrap
   * on a hot path. This byte-oriented variant lets `KeyManager` assemble the
   * password in a `Uint8Array` it can `.fill(0)` afterwards, so the key material
   * is not re-stringified per operation.
   */
  async deriveKeyBytes(
    passwordBytes: Uint8Array,
    salt: Uint8Array,
    iterations = PBKDF2_DEFAULT_ITERATIONS,
  ): Promise<Uint8Array> {
    const subtle = ensureWebCrypto();
    const baseKey = await subtle.importKey(
      'raw',
      passwordBytes as BufferSource,
      { name: 'PBKDF2' },
      false,
      ['deriveBits'],
    );
    const bits = await subtle.deriveBits(
      { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' },
      baseKey,
      32 * 8,
    );
    return new Uint8Array(bits);
  }

  /**
   * Generate HMAC-SHA256 over `data` keyed by `key`. Returns
   * lowercase hex.
   */
  async generateHMAC(data: Uint8Array, key: Uint8Array): Promise<string> {
    const subtle = ensureWebCrypto();
    const cryptoKey = await subtle.importKey(
      'raw',
      key as BufferSource,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const sig = await subtle.sign('HMAC', cryptoKey, data as BufferSource);
    return bytesToHex(new Uint8Array(sig));
  }

  /**
   * Verify HMAC-SHA256 in constant time. Compares hex strings via
   * Web Crypto `verify` to avoid the timing leaks a `===` on hex
   * would introduce.
   */
  async verifyHMAC(
    data: Uint8Array,
    key: Uint8Array,
    expectedHmacHex: string,
  ): Promise<boolean> {
    const subtle = ensureWebCrypto();
    const cryptoKey = await subtle.importKey(
      'raw',
      key as BufferSource,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const expected = hexToBytes(expectedHmacHex);
    return subtle.verify(
      'HMAC',
      cryptoKey,
      expected as BufferSource,
      data as BufferSource,
    );
  }

  hexToBytes(hex: string): Uint8Array {
    return hexToBytes(hex);
  }

  bytesToHex(bytes: Uint8Array): string {
    return bytesToHex(bytes);
  }

  stringToBytes(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }

  bytesToString(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += (bytes[i] as number).toString(16).padStart(2, '0');
  }
  return s;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
