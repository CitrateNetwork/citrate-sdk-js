/**
 * PBA-L4-001 (CRITICAL) and PBA-L4-005 (MEDIUM), 2026-09-24 pre-bounty audit.
 *
 * L4-001: with `thresholdShares > 0`, `encryptModel` put every Shamir share of
 * the model AES key into `metadata.keyShares`, and `deployModel` JSON-encoded
 * that metadata into the public INFERENCE_DEPLOY calldata. Anyone reading the
 * chain rebuilt the key from the calldata alone.
 *
 * Fix under test: shares never go into deploy metadata. Each share is wrapped
 * to a named holder public key with the ECDH V2 envelope and handed back to the
 * caller for off-chain delivery. With `thresholdShares > 0` and no holder keys,
 * encryption refuses.
 *
 * These tests drive the real entry point (`CitrateClient.deployModel`); only
 * `wallet.sendTransaction` is replaced, to capture the calldata. The leak check
 * is scripts/keyshare-leak-tripwire.js, which has its own GF(2^8) code so it
 * does not depend on the Shamir implementation it is checking.
 *
 * L4-005: `reconstructSecretBytes` accepted a share at x = 0 (whose y is the
 * secret), duplicate x values, and non-integer x; the key-reconstruct helper
 * took its threshold from the untrusted share; `verifyShares` only checked that
 * interpolation did not throw.
 */
import * as fs from 'fs';
import * as path from 'path';
import { ethers } from 'ethers';
import { CitrateClient } from '../../src/client/CitrateClient';
import { KeyManager } from '../../src/crypto/KeyManager';
import { CryptoManager } from '../../src/crypto/CryptoManager';
import {
  ShamirSecretSharing,
  reconstructSecretBytes,
  splitSecretBytes,
} from '../../src/crypto/FiniteField';
import { AccessType, ModelConfig, ModelType } from '../../src/types/Model';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { revealsKey } = require('../../scripts/keyshare-leak-tripwire.js') as {
  revealsKey: (calldata: string, key: Uint8Array) => { reveals: boolean; how?: string };
};

const OWNER_KEY = '0x' + '11'.repeat(32);
const HOLDER_KEYS = ['0x' + '22'.repeat(32), '0x' + '33'.repeat(32), '0x' + '44'.repeat(32)];
const OUTSIDER_KEY = '0x' + '55'.repeat(32);
const MODEL = new TextEncoder().encode('proprietary-model-weights');

interface Captured {
  data: string;
}

function clientWithCapture(): { client: CitrateClient; captured: Captured[]; send: jest.Mock } {
  const client = new CitrateClient({ rpcUrl: 'http://127.0.0.1:8545', privateKey: OWNER_KEY });
  const captured: Captured[] = [];
  const send = jest.fn(async (tx: Captured) => {
    captured.push({ data: tx.data });
    return {
      hash: '0x' + 'ab'.repeat(32),
      wait: async () => ({
        logs: [{ topics: [ethers.id('ModelDeployed(bytes32,address)')], data: '0x' + 'ab'.repeat(64) }],
        gasUsed: 21000n,
      }),
    };
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (client as any).wallet.sendTransaction = send;
  return { client, captured, send };
}

function config(extra: Record<string, unknown>): ModelConfig {
  return {
    name: 'm',
    modelType: ModelType.ONNX,
    accessType: AccessType.PUBLIC,
    accessPrice: 0n,
    encrypted: true,
    encryptionConfig: {
      algorithm: 'AES-256-GCM',
      keyDerivation: 'HKDF-SHA256',
      accessControl: true,
      thresholdShares: 2,
      totalShares: 3,
      ...extra,
    },
  } as ModelConfig;
}

/** The owner can always unwrap the model key; the test uses that as ground truth. */
async function ownerKeyFromCalldata(data: string): Promise<Uint8Array> {
  const payload = JSON.parse(ethers.toUtf8String(data));
  const owner = new KeyManager(OWNER_KEY);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (owner as any).decryptKeyFromOwner(payload.metadata.encryption.encryptedKey);
}

const holderPubs = () => HOLDER_KEYS.map((k) => new KeyManager(k).getPublicKey());

describe('PBA-L4-001: deploy calldata never carries key shares', () => {
  it('refuses thresholdShares > 0 without holder public keys, before any upload or send', async () => {
    const { client, send } = clientWithCapture();
    await expect(client.deployModel(MODEL, config({}))).rejects.toThrow(/shareHolderPublicKeys/);
    expect(send).not.toHaveBeenCalled();
  });

  it('KeyManager.encryptModel refuses thresholdShares > 0 without holder keys', async () => {
    const km = new KeyManager(OWNER_KEY);
    await expect(
      km.encryptModel(MODEL, config({}).encryptionConfig),
    ).rejects.toThrow(/shareHolderPublicKeys/);
  });

  it('no subset of the deploy calldata reconstructs the model key (holder-wrapped shares)', async () => {
    const { client, captured } = clientWithCapture();
    const dep = await client.deployModel(MODEL, config({ shareHolderPublicKeys: holderPubs() }));
    expect(captured).toHaveLength(1);
    const key = await ownerKeyFromCalldata(captured[0]!.data);
    expect(key.length).toBe(32);
    const verdict = revealsKey(captured[0]!.data, key);
    expect(verdict).toEqual({ reveals: false });
    // Nothing share-shaped reaches the chain at all.
    const text = ethers.toUtf8String(captured[0]!.data);
    expect(text).not.toMatch(/keyShares|keyShareEnvelopes|wrappedKey/);
    // The wrapped shares come back to the caller for off-chain delivery.
    expect(dep.keyShareEnvelopes).toHaveLength(3);
  });

  it('each holder unwraps only its own share; threshold holders rebuild the key; outsiders cannot', async () => {
    const { client, captured } = clientWithCapture();
    const dep = await client.deployModel(MODEL, config({ shareHolderPublicKeys: holderPubs() }));
    const key = await ownerKeyFromCalldata(captured[0]!.data);
    const ownerPub = new KeyManager(OWNER_KEY).getPublicKey();
    const envs = dep.keyShareEnvelopes!;

    const s0 = await new KeyManager(HOLDER_KEYS[0]).unwrapKeyShare(envs[0]!, ownerPub);
    const s2 = await new KeyManager(HOLDER_KEYS[2]).unwrapKeyShare(envs[2]!, ownerPub);
    const rebuilt = new KeyManager(HOLDER_KEYS[0]).reconstructKeyFromShares([s0, s2], 2);
    expect(Buffer.from(rebuilt).equals(Buffer.from(key))).toBe(true);

    // Holder 1 cannot open holder 0's envelope, and neither can an outsider.
    await expect(new KeyManager(HOLDER_KEYS[1]).unwrapKeyShare(envs[0]!, ownerPub)).rejects.toThrow();
    await expect(new KeyManager(OUTSIDER_KEY).unwrapKeyShare(envs[0]!, ownerPub)).rejects.toThrow();
  });

  it('rejects a holder list that does not name exactly one distinct key per share', async () => {
    const km = new KeyManager(OWNER_KEY);
    const pubs = holderPubs();
    const base = config({}).encryptionConfig!;
    await expect(km.encryptModel(MODEL, { ...base, shareHolderPublicKeys: pubs.slice(0, 2) })).rejects.toThrow(
      /one holder public key per share/,
    );
    await expect(
      km.encryptModel(MODEL, { ...base, shareHolderPublicKeys: [pubs[0]!, pubs[0]!, pubs[1]!] }),
    ).rejects.toThrow(/distinct/);
  });

  it('deployModel refuses caller metadata that smuggles share material into calldata', async () => {
    const { client, send } = clientWithCapture();
    const cfg: ModelConfig = {
      ...config({ thresholdShares: 0, totalShares: 0 }),
      metadata: { nested: { keyShares: [{ x: '1', y: 'ab', threshold: '1' }] } },
    };
    await expect(client.deployModel(MODEL, cfg)).rejects.toThrow(/key-share material/);
    expect(send).not.toHaveBeenCalled();
  });

  it('thresholdShares = 0 still deploys, and its calldata does not reveal the key', async () => {
    const { client, captured } = clientWithCapture();
    await client.deployModel(MODEL, config({ thresholdShares: 0, totalShares: 0 }));
    const key = await ownerKeyFromCalldata(captured[0]!.data);
    expect(revealsKey(captured[0]!.data, key)).toEqual({ reveals: false });
  });

  it('tripwire self-test: the pre-fix metadata shape IS flagged', () => {
    const cm = new CryptoManager();
    const key = cm.generateRandomBytes(32);
    const shares = splitSecretBytes(key, 2, 3).map(({ x, y }) => ({
      x: String(x),
      y: cm.bytesToHex(y),
      threshold: '2',
    }));
    const data = ethers.hexlify(
      ethers.toUtf8Bytes(JSON.stringify({ metadata: { encryption: { keyShares: shares } } })),
    );
    expect(revealsKey(data, key).reveals).toBe(true);
    // Bare y values with the x stripped are still caught.
    const bare = ethers.hexlify(
      ethers.toUtf8Bytes(JSON.stringify({ a: shares[0]!.y, b: shares[2]!.y })),
    );
    expect(revealsKey(bare, key).reveals).toBe(true);
  });

  it('source tripwire: no production file builds a keyShares field for calldata', () => {
    const srcDir = path.join(__dirname, '../../src');
    const offenders: string[] = [];
    const walk = (d: string) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (p.endsWith('.ts')) {
          const src = fs.readFileSync(p, 'utf8');
          // `keyShares` may appear only in the deploy guard's deny-list.
          const hits = src.split('\n').filter((l) => /\bkeyShares\b/.test(l) && !/SHARE_FIELD_DENYLIST/.test(l));
          if (hits.length) offenders.push(`${path.relative(srcDir, p)}: ${hits.join(' | ')}`);
        }
      }
    };
    walk(srcDir);
    expect(offenders).toEqual([]);
  });
});

describe('PBA-L4-005: Shamir reconstruction validates its shares', () => {
  const secret = new Uint8Array([0x41, 0x42, 0x43]);

  it('rejects a share at x = 0 (its y would dictate the secret)', () => {
    const forged = [
      { x: 0, y: new Uint8Array([0x41, 0x42]) },
      { x: 1, y: new Uint8Array([0x99, 0x10]) },
      { x: 2, y: new Uint8Array([0x07, 0xee]) },
    ];
    expect(() => reconstructSecretBytes(forged, 3)).toThrow(/x must be an integer in 1\.\.255/);
  });

  it.each([256, 1.5, NaN, -1, Infinity])('rejects x = %p', (bad) => {
    const shares = splitSecretBytes(secret, 2, 3);
    const tampered = [{ x: bad, y: shares[0]!.y }, shares[1]!];
    expect(() => reconstructSecretBytes(tampered, 2)).toThrow(/x must be an integer in 1\.\.255/);
  });

  it('rejects duplicate x values', () => {
    const shares = splitSecretBytes(secret, 2, 3);
    expect(() => reconstructSecretBytes([shares[0]!, { x: shares[0]!.x, y: shares[1]!.y }], 2)).toThrow(
      /duplicate share x/,
    );
  });

  it('rejects mismatched y lengths across all shares, not just the first threshold', () => {
    const shares = splitSecretBytes(secret, 2, 3);
    const bad = [shares[0]!, shares[1]!, { x: 3, y: new Uint8Array([1]) }];
    expect(() => reconstructSecretBytes(bad, 2)).toThrow(/same length/);
  });

  it('rejects an empty share y', () => {
    expect(() =>
      reconstructSecretBytes([{ x: 1, y: new Uint8Array() }, { x: 2, y: new Uint8Array() }], 2),
    ).toThrow(/same length|empty/);
  });

  it('reconstructKeyFromShares takes the threshold from the caller, not the share', () => {
    const km = new KeyManager(OWNER_KEY);
    const cm = new CryptoManager();
    const shares = splitSecretBytes(secret, 3, 5).map(({ x, y }) => ({
      x: String(x),
      y: cm.bytesToHex(y),
      threshold: '1', // attacker lowers the embedded threshold
    }));
    expect(() => km.reconstructKeyFromShares(shares.slice(0, 2), 3)).toThrow(/Insufficient shares/);
    expect(Array.from(km.reconstructKeyFromShares(shares.slice(0, 3), 3))).toEqual(Array.from(secret));
  });

  it('reconstructKeyFromShares rejects a non-integer threshold', () => {
    const km = new KeyManager(OWNER_KEY);
    expect(() => km.reconstructKeyFromShares([{ x: '1', y: 'aa', threshold: '1' }], 0)).toThrow(/threshold/);
  });

  it('verifyShares detects a share that is off the polynomial', () => {
    const sss = new ShamirSecretSharing(2, 4);
    const shares = sss.splitSecret(secret);
    expect(sss.verifyShares(shares)).toBe(true);
    const y = new Uint8Array(shares[3]!.y);
    y[0] = y[0]! ^ 0x01;
    expect(sss.verifyShares([shares[0]!, shares[1]!, shares[2]!, { x: 4, y }])).toBe(false);
  });

  it('verifyShares rejects structurally invalid share sets', () => {
    const sss = new ShamirSecretSharing(2, 3);
    const shares = sss.splitSecret(secret);
    expect(sss.verifyShares([{ x: 0, y: shares[0]!.y }, shares[1]!, shares[2]!])).toBe(false);
    expect(sss.verifyShares([shares[0]!])).toBe(false);
  });

  it('valid shares still round-trip (any threshold subset)', () => {
    const shares = splitSecretBytes(secret, 3, 5);
    expect(Array.from(reconstructSecretBytes([shares[4]!, shares[1]!, shares[2]!], 3))).toEqual(
      Array.from(secret),
    );
  });
});
