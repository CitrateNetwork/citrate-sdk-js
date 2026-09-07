/**
 * RM-G.3 — sdk-js encryptData must ECDH-wrap the symmetric key to a recipient
 * and never ship it in cleartext (the JS twin of SDK_PYTHON-001). Tripwires
 * authored against the pre-fix behavior, which packed the raw key into the
 * envelope.
 */
import { KeyManager } from '../../src/crypto/KeyManager';

const SENDER_KEY =
  '0x0123456789012345678901234567890123456789012345678901234567890123';
const RECIPIENT_KEY =
  '0x0223456789012345678901234567890123456789012345678901234567890123';

describe('RM-G.3 — encryptData ECDH-wraps the key', () => {
  it('fails closed without a recipient public key', async () => {
    const km = new KeyManager(SENDER_KEY);
    await expect(km.encryptData(JSON.stringify({ secret: 'hi' }))).rejects.toThrow(
      /recipientPublicKey/
    );
  });

  it('never ships the raw symmetric key in the envelope', async () => {
    const sender = new KeyManager(SENDER_KEY);
    const recipient = new KeyManager(RECIPIENT_KEY);
    const env = await sender.encryptData(
      JSON.stringify({ secret: 'hi' }),
      recipient.getPublicKey()
    );
    const pkg = JSON.parse(env);
    expect(pkg.key).toBeUndefined();
    expect(pkg.wrappedKey).toBeDefined();
    expect(pkg.senderPublicKey).toBeDefined();
    // SJS-B-004 / SJS-B-009 / RC-8: the envelope is now V2 — a per-message
    // kdfSalt and both endpoint keys are bound into the KEK. V1 (constant
    // derivation, no key binding) is refused on read.
    expect(pkg.scheme).toBe('ecdh-secp256k1-aesgcm-v2');
    expect(pkg.kdfSalt).toBeDefined();
    expect(pkg.recipientPublicKey).toBeDefined();
  });

  it('round-trips: the intended recipient can decrypt', async () => {
    const sender = new KeyManager(SENDER_KEY);
    const recipient = new KeyManager(RECIPIENT_KEY);
    const plaintext = JSON.stringify({ secret: 'hi', n: 42 });
    const env = await sender.encryptData(plaintext, recipient.getPublicKey());
    await expect(recipient.decryptData(env)).resolves.toBe(plaintext);
  });
});
