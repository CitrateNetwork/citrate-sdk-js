/**
 * RM-G2.6 / audit SDK-01, SDK-02, SUP-04, SUP-05 — JS SDK dep hygiene
 * unit tests.
 *
 * Asserts the post-cleanup contract:
 *   - CryptoManager round-trips through Web Crypto only (no
 *     `crypto-js` import on the runtime path).
 *   - CitrateClient accepts both `string` and `string[]` for rpcUrl
 *     and exposes the full fallback list via `getRpcUrls()`.
 *   - When `ipfsApiUrl` is unset the SDK returns a deterministic
 *     `sha256:<hex>` content pointer instead of dialing
 *     `http://localhost:5001`.
 */

import { CryptoManager } from '../../src/crypto/CryptoManager';
import { CitrateClient } from '../../src/client/CitrateClient';

describe('RM-G2.6 — CryptoManager (Web Crypto only)', () => {
  const cm = new CryptoManager();

  test('hashData returns 64-char lowercase hex', async () => {
    const out = await cm.hashData(new TextEncoder().encode('hello'));
    expect(out).toHaveLength(64);
    expect(out).toMatch(/^[0-9a-f]{64}$/);
  });

  test('AES-256-GCM encrypt/decrypt round-trip', async () => {
    const key = cm.generateRandomBytes(32);
    const data = new TextEncoder().encode('RM-G2.6 round-trip');
    const enc = await cm.encryptAES(data, key);
    expect(enc.nonce).toHaveLength(12);
    expect(enc.authTag).toHaveLength(16);
    const dec = await cm.decryptAES(enc.ciphertext, key, enc.nonce, enc.authTag);
    expect(new TextDecoder().decode(dec)).toBe('RM-G2.6 round-trip');
  });

  test('PBKDF2 deriveKey is deterministic for the same (password, salt)', async () => {
    const salt = new Uint8Array(16).fill(0x42);
    const k1 = await cm.deriveKey('pw', salt, 1000);
    const k2 = await cm.deriveKey('pw', salt, 1000);
    expect(k1).toEqual(k2);
    expect(k1).toHaveLength(32);
  });

  test('HMAC-SHA256 verify returns true for matching, false otherwise', async () => {
    const key = cm.generateRandomBytes(32);
    const data = new TextEncoder().encode('rm-g2.6 hmac');
    const tag = await cm.generateHMAC(data, key);
    expect(await cm.verifyHMAC(data, key, tag)).toBe(true);
    const tampered = data.slice();
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;
    expect(await cm.verifyHMAC(tampered, key, tag)).toBe(false);
  });
});

describe('RM-G2.6 — CitrateClient multi-RPC + IPFS config', () => {
  test('accepts a single rpcUrl string (legacy shape)', () => {
    const c = new CitrateClient({ rpcUrl: 'https://rpc.citrate.ai' });
    expect(c.getRpcUrls()).toEqual(['https://rpc.citrate.ai']);
  });

  test('accepts an rpcUrl array and preserves order', () => {
    const c = new CitrateClient({
      rpcUrl: ['https://primary.example', 'https://backup.example'],
    });
    expect(c.getRpcUrls()).toEqual([
      'https://primary.example',
      'https://backup.example',
    ]);
  });

  test('rejects an empty rpcUrl array up-front', () => {
    expect(() => new CitrateClient({ rpcUrl: [] as string[] })).toThrow(
      /must not be empty/,
    );
  });

  test('uploadToIPFS returns sha256:<hex> when ipfsApiUrl is unset', async () => {
    // The new fallback behaviour: no IPFS endpoint configured →
    // the SDK does not dial localhost. Reach into the private method
    // via a typed cast so the test exercises it directly.
    const c = new CitrateClient({ rpcUrl: 'https://rpc.citrate.ai' });
    const data = new TextEncoder().encode('payload');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const result = await (c as any).uploadToIPFS(data);
    expect(result).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});
