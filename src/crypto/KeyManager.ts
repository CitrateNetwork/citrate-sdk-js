/**
 * Key management for Citrate JavaScript SDK
 */

import { ethers } from 'ethers';
import { CryptoManager } from './CryptoManager';
import { splitSecretBytes, reconstructSecretBytes } from './FiniteField';
import { EncryptionConfig } from '../types/Model';
import { CitrateError } from '../errors/CitrateError';

/// RM-G.3 — envelope scheme tag for the ECDH-wrapped format (the JS twin
/// of SDK_PYTHON-001). The symmetric key is ECDH-wrapped to the recipient
/// and never shipped beside the ciphertext.
///
/// V2 (SJS-B-004 / SJS-B-009, mirrors citrate-sdk-python ECDH_SCHEME_V2): the KEK
/// is HKDF-SHA256(ECDH-x, salt=per-message kdfSalt, info=both endpoint keys)
/// instead of a bare unsalted SHA-256 of a mis-sliced x-coordinate. V1 (constant
/// derivation, no key binding) and the pre-2026-06 cleartext-key envelope are
/// REFUSED on read — see `decryptData`.
const ECDH_SCHEME_V2 = 'ecdh-secp256k1-aesgcm-v2';
const KEK_INFO_PREFIX = 'citrate-ecdh-v2|';

/**
 * FORWARD SECRECY — what this scheme does NOT give you (mirrors Python
 * CIT-SDKPY-01). The ECDH is STATIC-STATIC: both the sender's and the
 * recipient's keys are long-lived wallet keys, and there is no ephemeral
 * keypair. So the envelope is authenticated (only the holder of the sender key
 * could have produced it) but it is NOT forward-secret: anyone who later
 * compromises either static private key can re-derive the KEK and decrypt every
 * envelope ever exchanged between that pair. The per-message `kdfSalt`
 * randomizes the KEK per message but does not add forward secrecy — the salt
 * travels in the envelope. Do not describe this envelope as forward-secret.
 */

/** Canonical uncompressed public-key hex (no `0x`, lowercase, `04`-prefixed). */
function canonicalPubHex(key: string): string {
  const withPrefix = key.startsWith('0x') ? key : '0x' + key;
  return ethers.SigningKey.computePublicKey(withPrefix, false).slice(2).toLowerCase();
}

/** HKDF `info` binding both endpoint public keys so a swapped key changes the KEK. */
function kekInfo(senderPubHex: string, recipientPubHex: string): Uint8Array {
  return new TextEncoder().encode(`${KEK_INFO_PREFIX}${senderPubHex}|${recipientPubHex}`);
}

/** Constant-time-ish equality over two equal-length hex strings (public keys). */
function pubKeysEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export interface EncryptedModelResult {
  encryptedData: Uint8Array;
  metadata: {
    algorithm: string;
    nonce: string;
    keyDerivation: string;
    encryptedKey: string;
    accessControl: boolean;
    keyShares?: Array<{ x: string; y: string; threshold: string; }>;
  };
}

export class KeyManager {
  private wallet: ethers.Wallet | ethers.HDNodeWallet;
  private cryptoManager: CryptoManager;
  /** SJS-B-011: cache the derived public key so `getPublicKey()` does not build
   *  a throwaway `new ethers.Wallet(privateKey)` (a fresh private-key copy) on
   *  every call — it is invariant for the life of the object. */
  private publicKeyCache?: string;

  constructor(privateKey?: string) {
    if (privateKey) {
      this.wallet = new ethers.Wallet(privateKey);
    } else {
      this.wallet = ethers.Wallet.createRandom();
    }
    this.cryptoManager = new CryptoManager();
  }

  /**
   * Get Ethereum address
   */
  getAddress(): string {
    return this.wallet.address;
  }

  /**
   * Get private key.
   *
   * SJS-B-011: this is a deliberate escape hatch that hands out the raw private
   * key as an (immutable, non-wipeable) JS string. Prefer the sign-only /
   * encrypt methods; a caller that logs, serializes, or stores the return value
   * leaks the key. Kept for interop with tools that need the raw key.
   */
  getPrivateKey(): string {
    return this.wallet.privateKey;
  }

  /**
   * Get public key for ECDH (uncompressed, `04`-prefixed hex, no `0x`).
   * Cached — see `publicKeyCache` (SJS-B-011).
   */
  getPublicKey(): string {
    if (this.publicKeyCache === undefined) {
      this.publicKeyCache = this.wallet.signingKey.publicKey.slice(2).toLowerCase();
    }
    return this.publicKeyCache;
  }

  /**
   * Sign transaction
   */
  async signTransaction(transaction: ethers.TransactionRequest): Promise<string> {
    const signedTx = await this.wallet.signTransaction(transaction);
    return signedTx;
  }

  /**
   * Encrypt model data
   */
  async encryptModel(
    modelData: Uint8Array,
    config?: EncryptionConfig
  ): Promise<EncryptedModelResult> {
    const algorithm = config?.algorithm || 'AES-256-GCM';
    const keyDerivation = config?.keyDerivation || 'HKDF-SHA256';

    // Generate random encryption key
    const encryptionKey = this.cryptoManager.generateRandomBytes(32);

    // Encrypt model data
    const encrypted = await this.cryptoManager.encryptAES(modelData, encryptionKey);

    // Encrypt the encryption key for owner
    const encryptedKey = await this.encryptKeyForOwner(encryptionKey);

    // Create metadata
    const metadata: {
      algorithm: string;
      nonce: string;
      keyDerivation: string;
      encryptedKey: string;
      accessControl: boolean;
      keyShares?: Array<{ x: string; y: string; threshold: string; }>;
    } = {
      algorithm,
      nonce: this.cryptoManager.bytesToHex(encrypted.nonce),
      keyDerivation,
      encryptedKey,
      // Use nullish coalescing: `|| true` coerced an explicit `false` to `true`,
      // so callers could not disable access control and the metadata misreported
      // the caller's choice. Audit: CITRATE_SDK_JS-B-2026-05-31-003.
      accessControl: config?.accessControl ?? true
    };

    // Add threshold sharing if enabled
    if (config?.thresholdShares && config.thresholdShares > 0) {
      const keyShares = this.createKeyShares(
        encryptionKey,
        config.thresholdShares,
        config.totalShares
      );
      metadata.keyShares = keyShares;
    }

    // Combine ciphertext and auth tag
    const encryptedData = new Uint8Array(encrypted.ciphertext.length + encrypted.authTag.length);
    encryptedData.set(encrypted.ciphertext);
    encryptedData.set(encrypted.authTag, encrypted.ciphertext.length);

    return {
      encryptedData,
      metadata
    };
  }

  /**
   * Decrypt model data
   */
  async decryptModel(
    encryptedData: Uint8Array,
    metadata: any
  ): Promise<Uint8Array> {
    // Extract ciphertext and auth tag
    const authTagLength = 16;
    const ciphertext = encryptedData.slice(0, -authTagLength);
    const authTag = encryptedData.slice(-authTagLength);
    const nonce = this.cryptoManager.hexToBytes(metadata.nonce);

    // Decrypt the encryption key
    const encryptionKey = await this.decryptKeyFromOwner(metadata.encryptedKey);

    // Decrypt model data
    const decrypted = await this.cryptoManager.decryptAES(
      ciphertext,
      encryptionKey,
      nonce,
      authTag
    );

    return decrypted;
  }

  /**
   * Encrypt arbitrary data
   */
  async encryptData(data: string, recipientPublicKey?: string): Promise<string> {
    // RM-G.3 / SDK_JS encryptData: the previous envelope shipped the raw AES
    // key beside the ciphertext — zero confidentiality once the envelope
    // lands on public inference calldata. A recipient public key is now
    // REQUIRED; the key is ECDH-wrapped to it and never appears raw. With no
    // recipient we fail closed rather than fabricate confidentiality.
    //
    // NOT forward-secret — see the module-level note. The wrap is static-static
    // ECDH; compromise of either static key retro-decrypts.
    if (!recipientPublicKey) {
      throw new CitrateError(
        'encryptData requires recipientPublicKey: the symmetric key is ECDH-wrapped ' +
          'to the recipient and never shipped in cleartext (SDK_JS encryptData fix).'
      );
    }
    const dataBytes = this.cryptoManager.stringToBytes(data);
    const key = this.cryptoManager.generateRandomBytes(32);

    const encrypted = await this.cryptoManager.encryptAES(dataBytes, key);

    // ECDH-wrap the symmetric key to the recipient (V2). The KEK is
    // HKDF-SHA256(ECDH-x, salt=fresh kdfSalt, info=both endpoint keys); the
    // recipient re-derives it from its own key + senderPublicKey + the salt and
    // keys carried in the envelope.
    const kdfSalt = this.cryptoManager.generateRandomBytes(32);
    const senderPub = this.getPublicKey();
    const recipientPub = canonicalPubHex(recipientPublicKey);
    const shared = await this.deriveSharedKey(recipientPub, {
      salt: kdfSalt,
      info: kekInfo(senderPub, recipientPub),
    });
    const wrapped = await this.cryptoManager.encryptAES(key, shared);
    // Best-effort wipe of transient key material (SJS-B-011); narrows the
    // window, JS cannot guarantee erasure.
    shared.fill(0);
    key.fill(0);

    const package_ = {
      scheme: ECDH_SCHEME_V2,
      ciphertext: this.cryptoManager.bytesToHex(encrypted.ciphertext),
      nonce: this.cryptoManager.bytesToHex(encrypted.nonce),
      authTag: this.cryptoManager.bytesToHex(encrypted.authTag),
      wrappedKey: this.cryptoManager.bytesToHex(wrapped.ciphertext),
      wrapNonce: this.cryptoManager.bytesToHex(wrapped.nonce),
      wrapAuthTag: this.cryptoManager.bytesToHex(wrapped.authTag),
      kdfSalt: this.cryptoManager.bytesToHex(kdfSalt),
      senderPublicKey: senderPub,
      recipientPublicKey: recipientPub,
    };

    return JSON.stringify(package_);
  }

  /**
   * Decrypt a V2 ECDH-wrapped envelope. FAILS CLOSED on anything else.
   *
   * @param expectedSenderPublicKey - hex public key the envelope MUST claim.
   *   Pass this whenever origin matters. Static-static ECDH already guarantees
   *   the envelope was produced by the holder of `senderPublicKey` — an attacker
   *   cannot relabel their envelope as coming from someone else — but it cannot
   *   tell you whether that key is one you trust: anyone may send you a perfectly
   *   valid envelope under their own key. Omitting this authenticates nothing
   *   about WHO, and callers routinely read a successful decrypt as trust.
   *
   * SJS-B-004 (mirrors Python SECREM-02 K3): this used to accept the legacy
   * cleartext-key envelope "for backward-compatible READS only". An audit PoC
   * confirmed the consequence: an attacker-supplied envelope carrying a raw key
   * of their choosing decrypted successfully — the AES-GCM tag verifies because
   * the attacker made it — and `inference()` JSON.parsed the result into the
   * caller's output. Producing the legacy form had been stopped; reading it had
   * not, so the downgrade survived the fix. It also accepted V1, whose KEK
   * derives from a constant with no binding of the endpoint keys. Both are now
   * refused.
   */
  async decryptData(encryptedPackage: string, expectedSenderPublicKey?: string): Promise<string> {
    const package_ = JSON.parse(encryptedPackage);

    // A cleartext `key` is hostile by construction — checked FIRST, before the
    // scheme, so an envelope carrying BOTH a wrappedKey and a cleartext key is
    // rejected outright rather than silently preferring the safe field (that
    // would still be processing a tampered envelope).
    if (package_.key !== undefined) {
      throw new CitrateError(
        'decryptData: refusing a cleartext-key envelope. The symmetric key must be ' +
          'ECDH-wrapped to the recipient. An envelope carrying a raw key is either ' +
          'pre-2026-06 (never confidential — re-encrypt it) or forged (SJS-B-004).'
      );
    }
    if (package_.scheme !== ECDH_SCHEME_V2) {
      throw new CitrateError(
        `decryptData: unsupported envelope scheme ${JSON.stringify(package_.scheme)}. ` +
          `This SDK reads only ${ECDH_SCHEME_V2}. V1 envelopes derived their key from a ` +
          'constant with no binding of the endpoint keys and are refused; re-encrypt ' +
          'with a current SDK (SJS-B-004).'
      );
    }
    for (const field of [
      'ciphertext', 'nonce', 'authTag', 'wrappedKey', 'wrapNonce', 'wrapAuthTag',
      'kdfSalt', 'senderPublicKey', 'recipientPublicKey',
    ]) {
      if (package_[field] === undefined) {
        throw new CitrateError(`decryptData: envelope is missing required field '${field}' (SJS-B-004).`);
      }
    }

    // Sender pinning, when the caller has an expectation. Compared BEFORE any
    // key derivation so a mismatch costs nothing.
    if (expectedSenderPublicKey !== undefined) {
      if (!pubKeysEqual(canonicalPubHex(package_.senderPublicKey), canonicalPubHex(expectedSenderPublicKey))) {
        throw new CitrateError(
          'decryptData: envelope sender does not match the expected sender — refusing to ' +
            'decrypt. The envelope is cryptographically valid but was produced by a ' +
            'different keypair (SJS-B-004).'
        );
      }
    }

    const ciphertext = this.cryptoManager.hexToBytes(package_.ciphertext);
    const nonce = this.cryptoManager.hexToBytes(package_.nonce);
    const authTag = this.cryptoManager.hexToBytes(package_.authTag);

    // Re-derive the KEK. Both endpoint keys and the salt come from the envelope
    // and all three feed the derivation, so tampering with any of them yields a
    // different KEK and the unwrap below fails its tag check — the binding is
    // enforced by the AEAD, not by a comparison we could forget to make.
    const shared = await this.deriveSharedKey(package_.senderPublicKey, {
      salt: this.cryptoManager.hexToBytes(package_.kdfSalt),
      info: kekInfo(
        canonicalPubHex(package_.senderPublicKey),
        canonicalPubHex(package_.recipientPublicKey),
      ),
    });
    let key: Uint8Array;
    try {
      key = await this.cryptoManager.decryptAES(
        this.cryptoManager.hexToBytes(package_.wrappedKey),
        shared,
        this.cryptoManager.hexToBytes(package_.wrapNonce),
        this.cryptoManager.hexToBytes(package_.wrapAuthTag)
      );
    } finally {
      shared.fill(0);
    }

    const decrypted = await this.cryptoManager.decryptAES(ciphertext, key, nonce, authTag);
    key.fill(0);
    return this.cryptoManager.bytesToString(decrypted);
  }

  /**
   * Derive the 32-byte ECDH key-encryption key.
   *
   * SJS-B-009: the old implementation hashed the wrong bytes — `slice(2, 66)` on
   * the `0x04‖x‖y` point took the `04` prefix plus the first 31 bytes of x,
   * DROPPING x's last byte, then bare-SHA-256'd it with no salt and no domain
   * separation. It also mangled any `0x`-prefixed or compressed peer key. Now:
   * the peer key is normalized to an uncompressed point (accepting `0x`-prefixed,
   * bare, and compressed 02/03 forms), the FULL 32-byte x-coordinate is taken,
   * and HKDF-SHA256(x, salt, info) derives the KEK — matching the Python SDK.
   */
  async deriveSharedKey(
    peerPublicKey: string,
    opts: { salt: Uint8Array; info: Uint8Array },
  ): Promise<Uint8Array> {
    const signingKey = this.wallet.signingKey;
    const normalized = canonicalPubHex(peerPublicKey); // uncompressed, no 0x
    const sharedPoint = signingKey.computeSharedSecret('0x' + normalized); // 0x04 ‖ x ‖ y
    // Full 32-byte x-coordinate: skip '0x' (2) + '04' (2) = index 4, take 64 hex.
    const x = this.cryptoManager.hexToBytes(sharedPoint.slice(4, 68));
    const kek = await this.cryptoManager.hkdfSha256(x, opts.salt, opts.info, 32);
    x.fill(0);
    return kek;
  }

  /**
   * Encrypt key for model owner
   */
  private async encryptKeyForOwner(key: Uint8Array): Promise<string> {
    // Derive the owner-wrap key with a salted, iterated KDF (PBKDF2-SHA256) +
    // domain separation. The previous derivation was a single unsalted
    // SHA-256(privateKey) — deterministic and globally reusable across every
    // wrapped key. Audit: CITRATE_SDK_JS-2026-05-31-002 (HIGH).
    const salt = this.cryptoManager.generateRandomBytes(16);
    // SJS-B-011: build the PBKDF2 password as bytes we can wipe, rather than a
    // template literal that interns a fresh copy of the raw private key.
    const password = this.wrapPasswordBytes();
    const ownerKeyBytes = await this.cryptoManager.deriveKeyBytes(password, salt);
    password.fill(0);

    const encrypted = await this.cryptoManager.encryptAES(key, ownerKeyBytes);

    return JSON.stringify({
      v: 2,
      kdf: 'pbkdf2-sha256',
      salt: this.cryptoManager.bytesToHex(salt),
      encryptedKey: this.cryptoManager.bytesToHex(encrypted.ciphertext),
      nonce: this.cryptoManager.bytesToHex(encrypted.nonce),
      authTag: this.cryptoManager.bytesToHex(encrypted.authTag)
    });
  }

  /**
   * Decrypt key for model owner
   */
  private async decryptKeyFromOwner(encryptedKeyPackage: string): Promise<Uint8Array> {
    const package_ = JSON.parse(encryptedKeyPackage);

    let ownerKeyBytes: Uint8Array;
    if (typeof package_.salt === 'string' && package_.salt.length > 0) {
      // v2: salted PBKDF2 derivation (current). Audit CITRATE_SDK_JS-...-002.
      // SJS-B-011: wipeable byte password rather than a template literal.
      const password = this.wrapPasswordBytes();
      ownerKeyBytes = await this.cryptoManager.deriveKeyBytes(
        password,
        this.cryptoManager.hexToBytes(package_.salt)
      );
      password.fill(0);
    } else {
      // v1 legacy: unsalted SHA-256(privateKey). Retained read-only so packages
      // wrapped before the KDF hardening can still be decrypted (no regression).
      const legacyKey = await this.cryptoManager.hashData(
        this.cryptoManager.hexToBytes(this.wallet.privateKey.slice(2))
      );
      ownerKeyBytes = this.cryptoManager.hexToBytes(legacyKey);
    }

    const encryptedKey = this.cryptoManager.hexToBytes(package_.encryptedKey);
    const nonce = this.cryptoManager.hexToBytes(package_.nonce);
    const authTag = this.cryptoManager.hexToBytes(package_.authTag);

    return await this.cryptoManager.decryptAES(encryptedKey, ownerKeyBytes, nonce, authTag);
  }

  /**
   * Build the owner-wrap PBKDF2 password as wipeable bytes:
   * `utf8("citrate-model-key-wrap-v1:") ‖ privateKeyBytes` (SJS-B-011). The
   * caller `.fill(0)`s the returned array after deriving.
   */
  private wrapPasswordBytes(): Uint8Array {
    const domain = new TextEncoder().encode('citrate-model-key-wrap-v1:');
    const priv = this.cryptoManager.hexToBytes(this.wallet.privateKey.slice(2));
    const out = new Uint8Array(domain.length + priv.length);
    out.set(domain);
    out.set(priv, domain.length);
    priv.fill(0);
    return out;
  }

  /**
   * Create Shamir's secret shares for key using proper finite field arithmetic
   */
  private createKeyShares(
    key: Uint8Array,
    threshold: number,
    total: number
  ): Array<{ x: string; y: string; threshold: string }> {
    const sharesTuples = splitSecretBytes(key, threshold, total);

    return sharesTuples.map(({ x, y }) => ({
      x: x.toString(),
      y: this.cryptoManager.bytesToHex(y),
      threshold: threshold.toString()
    }));
  }

  /**
   * Reconstruct key from Shamir's shares using proper Lagrange interpolation
   */
  reconstructKeyFromShares(shares: Array<{ x: string; y: string; threshold: string }>): Uint8Array {
    if (!shares.length) {
      throw new Error('No shares provided');
    }

    const firstShare = shares[0];
    if (!firstShare) {
      throw new Error('Invalid shares array');
    }
    const threshold = parseInt(firstShare.threshold);
    if (shares.length < threshold) {
      throw new Error('Insufficient shares for key reconstruction');
    }

    // Convert shares back to tuples format
    const sharesTuples = shares.map(share => ({
      x: parseInt(share.x),
      y: this.cryptoManager.hexToBytes(share.y)
    }));

    return reconstructSecretBytes(sharesTuples, threshold);
  }
}