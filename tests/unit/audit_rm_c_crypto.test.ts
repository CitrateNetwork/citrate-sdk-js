/**
 * RM-C sdk-js crypto hardening — tripwire tests for the inaugural federation
 * deep audit. Each asserts behavior the pre-fix code violated:
 *   - CITRATE_SDK_JS-2026-05-31-001 (CRITICAL): Shamir coefficients from a CSPRNG, fail-closed.
 *   - CITRATE_SDK_JS-2026-05-31-002 (HIGH): salted PBKDF2 owner-key derivation (not unsalted SHA-256).
 *   - CITRATE_SDK_JS-B-2026-05-31-003 (MED): accessControl uses `?? true`, not `|| true`.
 */
import { ShamirSecretSharing } from '../../src/crypto/FiniteField';
import { KeyManager } from '../../src/crypto/KeyManager';

// A valid secp256k1 test key (non-zero, < curve order). Test-only.
const TEST_KEY =
  '0x0123456789012345678901234567890123456789012345678901234567890123';

describe('RM-C CITRATE_SDK_JS-001 — CSPRNG Shamir coefficients', () => {
  it('produces fresh CSPRNG coefficients per split (non-deterministic shares)', () => {
    const sss = new ShamirSecretSharing(3, 5);
    const secret = new Uint8Array([1, 2, 3, 42, 255, 0, 128]);
    const a = sss.splitSecret(secret);
    const b = sss.splitSecret(secret);
    expect(a).toHaveLength(5);
    // Same secret, fresh CSPRNG coefficients each call → shares differ.
    const aFlat = a.flatMap((s) => Array.from(s.y));
    const bFlat = b.flatMap((s) => Array.from(s.y));
    expect(aFlat).not.toEqual(bFlat);
  });

  it('splits and reconstructs a secret from any threshold subset of shares', () => {
    const sss = new ShamirSecretSharing(3, 5);
    const secret = new Uint8Array([1, 2, 3, 42, 255, 0, 128]);
    const shares = sss.splitSecret(secret);
    expect(shares).toHaveLength(5);
    // First 3 shares.
    expect(Array.from(sss.reconstructSecret(shares.slice(0, 3)))).toEqual(
      Array.from(secret),
    );
    // A different subset of 3 shares (any t-of-n combination must recover).
    expect(Array.from(sss.reconstructSecret([shares[1]!, shares[3]!, shares[4]!]))).toEqual(
      Array.from(secret),
    );
  });

  it('round-trips repeatedly (no intermittent reconstruction failures)', () => {
    const sss = new ShamirSecretSharing(2, 3);
    for (let t = 0; t < 50; t++) {
      const secret = new Uint8Array([t & 0xff, (t * 7) & 0xff, 0, 255]);
      const shares = sss.splitSecret(secret);
      expect(Array.from(sss.reconstructSecret(shares.slice(0, 2)))).toEqual(
        Array.from(secret),
      );
    }
  });

  it('FAILS CLOSED when no CSPRNG is available (never silently uses a weak RNG)', () => {
    const sss = new ShamirSecretSharing(3, 5);
    const saved = (globalThis as { crypto?: unknown }).crypto;
    // Remove the Web Crypto CSPRNG for the duration of this synchronous call.
    (globalThis as { crypto?: unknown }).crypto = {} as unknown;
    try {
      expect(() => sss.splitSecret(new Uint8Array([1, 2, 3]))).toThrow(
        /cryptographically secure/i,
      );
    } finally {
      (globalThis as { crypto?: unknown }).crypto = saved;
    }
  });
});

describe('RM-C CITRATE_SDK_JS-002 — salted owner-key derivation', () => {
  it('wraps the model key with a per-encryption salt and round-trips', async () => {
    const km = new KeyManager(TEST_KEY);
    const data = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2, 1]);

    const enc1 = await km.encryptModel(data);
    const pkg1 = JSON.parse(enc1.metadata.encryptedKey);
    expect(typeof pkg1.salt).toBe('string');
    expect(pkg1.salt.length).toBeGreaterThan(0);

    // A second wrap of the same data must use a different salt (non-deterministic).
    const enc2 = await km.encryptModel(data);
    const pkg2 = JSON.parse(enc2.metadata.encryptedKey);
    expect(pkg2.salt).not.toEqual(pkg1.salt);

    // Round-trip still works.
    const recovered = await km.decryptModel(enc1.encryptedData, enc1.metadata);
    expect(Array.from(recovered)).toEqual(Array.from(data));
  });
});

describe('RM-C CITRATE_SDK_JS-B-003 — accessControl nullish coalescing', () => {
  it('honors an explicit accessControl=false (not coerced to true)', async () => {
    const km = new KeyManager(TEST_KEY);
    const enc = await km.encryptModel(new Uint8Array([1, 2, 3]), {
      algorithm: 'AES-256-GCM',
      keyDerivation: 'PBKDF2-SHA256',
      accessControl: false,
      thresholdShares: 0,
      totalShares: 0,
    });
    expect(enc.metadata.accessControl).toBe(false);
  });
});
