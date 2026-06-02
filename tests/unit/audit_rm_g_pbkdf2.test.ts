/** RM-G.7 — PBKDF2 default iterations must meet OWASP guidance (>= 600k). */
import { PBKDF2_DEFAULT_ITERATIONS, CryptoManager } from '../../src/crypto/CryptoManager';

describe('RM-G.7 — PBKDF2 default iterations', () => {
  it('meets OWASP PBKDF2-SHA256 guidance (>= 600,000)', () => {
    expect(PBKDF2_DEFAULT_ITERATIONS).toBeGreaterThanOrEqual(600_000);
  });

  it('deriveKey still produces a 32-byte key with the default work factor', async () => {
    const cm = new CryptoManager();
    const salt = cm.generateRandomBytes(16);
    const key = await cm.deriveKey('pw', salt);
    expect(key.length).toBe(32);
  });
});
