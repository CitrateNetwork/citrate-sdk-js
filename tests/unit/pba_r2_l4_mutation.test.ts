/**
 * Mutation-hardening tests for the PBA-L4-001 / PBA-L4-005 fix. Each block
 * kills Stryker survivors from the first run (boundaries, messages, guards)
 * in FiniteField.ts, KeyManager.ts, shareGuard.ts and CitrateClient.deployModel.
 */
import { ethers } from 'ethers';
import { CitrateClient } from '../../src/client/CitrateClient';
import { KeyManager } from '../../src/crypto/KeyManager';
import { ShamirSecretSharing, reconstructSecretBytes, splitSecretBytes } from '../../src/crypto/FiniteField';
import { assertNoKeyShareMaterial, SHARE_FIELD_DENYLIST } from '../../src/crypto/shareGuard';
import { AccessType, EncryptionConfig, ModelConfig, ModelType } from '../../src/types/Model';

const OWNER = '0x' + '11'.repeat(32);
const MODEL = new TextEncoder().encode('weights');
const secret = new Uint8Array([7, 8, 9]);
const keyFor = (i: number) => '0x' + (i + 1).toString(16).padStart(64, '0');
const pubs = (n: number) => Array.from({ length: n }, (_, i) => new KeyManager(keyFor(i + 100)).getPublicKey());
const enc = (extra: Partial<EncryptionConfig>): EncryptionConfig => ({
  algorithm: 'AES-256-GCM',
  keyDerivation: 'HKDF-SHA256',
  accessControl: true,
  thresholdShares: 2,
  totalShares: 3,
  ...extra,
});

describe('ShamirSecretSharing constructor bounds', () => {
  it.each([
    [1.5, 3, /integers/],
    [2, 3.5, /integers/],
    [0, 3, /positive/],
    [4, 3, /cannot exceed total/],
    [2, 256, /cannot exceed 255/],
  ])('(%p, %p) throws', (t, n, re) => {
    expect(() => new ShamirSecretSharing(t as number, n as number)).toThrow(re as RegExp);
  });
  it('accepts (1, 1) and (255, 255)', () => {
    expect(() => new ShamirSecretSharing(1, 1)).not.toThrow();
    expect(() => new ShamirSecretSharing(255, 255)).not.toThrow();
  });
});

describe('share validation edges', () => {
  it('empty share list', () => {
    expect(() => reconstructSecretBytes([], 1)).toThrow(/No shares provided/);
  });
  it('null / missing entries fail with a validation error, not a TypeError', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => reconstructSecretBytes([null as any, { x: 1, y: new Uint8Array([1]) }], 1)).toThrow(/Invalid share/);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => reconstructSecretBytes([{ x: 1 } as any], 1)).toThrow(/Invalid share/);
  });
  it('x = 255 is valid', () => {
    expect(Array.from(reconstructSecretBytes([{ x: 255, y: new Uint8Array([5]) }], 1))).toEqual([5]);
  });
  it('too few shares reports the threshold (not a constructor error)', () => {
    const s = splitSecretBytes(secret, 3, 5);
    expect(() => reconstructSecretBytes(s.slice(0, 2), 3)).toThrow(/Need at least 3 shares, got 2/);
    expect(() => new ShamirSecretSharing(3, 5).reconstructSecret(s.slice(0, 2))).toThrow(/Need at least 3/);
  });
  it('uses only the first threshold shares (a trailing bad share does not change the result)', () => {
    const s = splitSecretBytes(secret, 2, 3);
    const bad = { x: 3, y: new Uint8Array([0xde, 0xad, 0xbe]) };
    expect(Array.from(reconstructSecretBytes([s[0]!, s[1]!, bad], 2))).toEqual(Array.from(secret));
  });
});

describe('verifyShares edges', () => {
  const sss = new ShamirSecretSharing(2, 3);
  it('exactly threshold valid shares are consistent', () => {
    expect(sss.verifyShares(sss.splitSecret(secret).slice(0, 2))).toBe(true);
  });
  it('a duplicated share returns false instead of throwing', () => {
    const s = sss.splitSecret(secret);
    expect(sss.verifyShares([s[0]!, s[0]!, s[1]!])).toBe(false);
  });
});

describe('encryptModel share-plan validation', () => {
  const km = new KeyManager(OWNER);
  it.each([
    [{ thresholdShares: 1.5 }, /invalid share parameters/],
    [{ totalShares: 2.5 }, /invalid share parameters/],
    [{ thresholdShares: 4, totalShares: 3 }, /invalid share parameters/],
    [{ thresholdShares: 2, totalShares: 256 }, /invalid share parameters/],
    [{ thresholdShares: -1 }, /invalid share parameters.*need integers with 1 <= thresholdShares <= totalShares <= 255/],
  ])('%p rejected', async (extra, re) => {
    await expect(km.encryptModel(MODEL, enc({ ...extra, shareHolderPublicKeys: pubs(3) }))).rejects.toThrow(re);
  });
  it('an empty holder list is refused with guidance', async () => {
    await expect(km.encryptModel(MODEL, enc({ shareHolderPublicKeys: [] }))).rejects.toThrow(
      /requires shareHolderPublicKeys.*never written to deploy metadata.*returned for off-chain delivery \(PBA-L4-001\)\. Pass one holder public key per share, or set thresholdShares to 0/s,
    );
  });
  it('count mismatch names both numbers', async () => {
    await expect(km.encryptModel(MODEL, enc({ shareHolderPublicKeys: pubs(2) }))).rejects.toThrow(
      /totalShares=3, shareHolderPublicKeys has 2/,
    );
  });
  it('duplicate holders: message explains why', async () => {
    const p = pubs(2);
    await expect(km.encryptModel(MODEL, enc({ shareHolderPublicKeys: [p[0]!, p[1]!, p[0]!] }))).rejects.toThrow(
      /must be distinct; one holder with several shares defeats the threshold/,
    );
  });
  it('an invalid public key is refused', async () => {
    await expect(km.encryptModel(MODEL, enc({ shareHolderPublicKeys: ['zz', 'yy', 'xx'] }))).rejects.toThrow(
      /invalid secp256k1 public key/,
    );
  });
  it('boundaries accepted: 1-of-1, 3-of-3', async () => {
    const r1 = await km.encryptModel(MODEL, enc({ thresholdShares: 1, totalShares: 1, shareHolderPublicKeys: pubs(1) }));
    expect(r1.keyShareEnvelopes).toHaveLength(1);
    const r3 = await km.encryptModel(MODEL, enc({ thresholdShares: 3, totalShares: 3, shareHolderPublicKeys: pubs(3) }));
    expect(r3.metadata.keySharing).toEqual({ threshold: 3, totalShares: 3 });
  });
  it('255 shares accepted', async () => {
    const r = await km.encryptModel(MODEL, enc({ thresholdShares: 2, totalShares: 255, shareHolderPublicKeys: pubs(255) }));
    expect(r.keyShareEnvelopes).toHaveLength(255);
    expect(r.keyShareEnvelopes![254]!.x).toBe(255);
  }, 60000);
  it('metadata defaults and keySharing record', async () => {
    const r = await km.encryptModel(MODEL, enc({ shareHolderPublicKeys: pubs(3) }));
    expect(r.metadata.keySharing).toEqual({ threshold: 2, totalShares: 3 });
    const d = await km.encryptModel(MODEL);
    expect(d.metadata.algorithm).toBe('AES-256-GCM');
    expect(d.metadata.keyDerivation).toBe('HKDF-SHA256');
    expect(d.metadata.accessControl).toBe(true);
    expect(d.metadata.keySharing).toBeUndefined();
    expect(d.keyShareEnvelopes).toBeUndefined();
    const f = await km.encryptModel(MODEL, enc({ thresholdShares: 0, accessControl: false, algorithm: 'X', keyDerivation: 'Y' }));
    expect([f.metadata.algorithm, f.metadata.keyDerivation, f.metadata.accessControl]).toEqual(['X', 'Y', false]);
  });
  it('unwrapKeyShare names the addressing error', async () => {
    const r = await km.encryptModel(MODEL, enc({ shareHolderPublicKeys: pubs(3) }));
    await expect(
      new KeyManager(keyFor(101)).unwrapKeyShare(r.keyShareEnvelopes![0]!, km.getPublicKey()),
    ).rejects.toThrow(/addressed to a different holder/);
  });
});

describe('reconstructKeyFromShares input checks', () => {
  const km = new KeyManager(OWNER);
  const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
  it('threshold 1 and 255 accepted; 256 rejected', () => {
    const one = splitSecretBytes(secret, 1, 12).map(({ x, y }) => ({ x: String(x), y: hex(y) }));
    expect(Array.from(km.reconstructKeyFromShares([one[11]!], 1))).toEqual(Array.from(secret));
    const all = splitSecretBytes(secret, 255, 255).map(({ x, y }) => ({ x: String(x), y: hex(y) }));
    expect(Array.from(km.reconstructKeyFromShares(all, 255))).toEqual(Array.from(secret));
    expect(() => km.reconstructKeyFromShares(all, 256)).toThrow(/threshold must be an integer in 1\.\.255/);
  });
  it('empty list', () => {
    expect(() => km.reconstructKeyFromShares([], 1)).toThrow(/No shares provided/);
  });
  it.each([' 1', '1 ', '0x1', '1a', '1000'])('x = %p rejected', (x) => {
    expect(() => km.reconstructKeyFromShares([{ x, y: 'aa' }], 1)).toThrow(/x must be an integer in 1\.\.255/);
  });
});

describe('assertNoKeyShareMaterial', () => {
  it.each(SHARE_FIELD_DENYLIST.map((k) => [k]))('rejects %s', (k) => {
    expect(() => assertNoKeyShareMaterial({ a: [{ [k]: [] }] })).toThrow(
      new RegExp(`key-share material \\('${k}'\\) in public deploy calldata\\. Deliver key shares to their holders off-chain`),
    );
  });
  it('covers exactly the four share field names', () => {
    expect([...SHARE_FIELD_DENYLIST].sort()).toEqual(['keyShareEnvelopes', 'keyShares', 'key_share_envelopes', 'key_shares']);
  });
  it('allows nulls, primitives and ordinary nesting', () => {
    expect(() => assertNoKeyShareMaterial({ a: null, b: 1, c: 'keyShares', d: [1, { e: null }] })).not.toThrow();
  });
  it('refuses payloads nested deeper than it scans', () => {
    const nest = (n: number): Record<string, unknown> => (n === 0 ? { leaf: 1 } : { n: nest(n - 1) });
    expect(() => assertNoKeyShareMaterial(nest(32))).not.toThrow();
    expect(() => assertNoKeyShareMaterial(nest(33))).toThrow(/nested more than 32 levels deep; refusing to publish calldata that cannot be fully checked/);
  });
});

describe('deployModel unencrypted path is unchanged', () => {
  it('sends plaintext metadata with no encryption block and an empty accessList', async () => {
    const client = new CitrateClient({ rpcUrl: 'http://127.0.0.1:8545', privateKey: OWNER });
    const sent: string[] = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (client as any).wallet.sendTransaction = async (tx: { data: string }) => {
      sent.push(tx.data);
      return {
        hash: '0x' + 'ab'.repeat(32),
        wait: async () => ({ logs: [{ topics: [ethers.id('ModelDeployed(bytes32,address)')], data: '0x' + 'ab'.repeat(64) }], gasUsed: 1n }),
      };
    };
    const cfg: ModelConfig = { name: 'm', modelType: ModelType.ONNX, accessType: AccessType.PUBLIC, accessPrice: 0n, encrypted: false };
    const dep = await client.deployModel(MODEL, cfg);
    const payload = JSON.parse(ethers.toUtf8String(sent[0]!));
    expect(payload.encrypted).toBe(false);
    expect(payload.accessList).toEqual([]);
    expect(payload.metadata).toEqual({});
    expect(dep.keyShareEnvelopes).toBeUndefined();
  });
});

describe('deployModel pre-existing guards on the changed function', () => {
  const cfg: ModelConfig = { name: 'm', modelType: ModelType.ONNX, accessType: AccessType.PUBLIC, accessPrice: 0n, encrypted: true };
  it('encrypted without a KeyManager refuses with the plaintext-upload message', async () => {
    const client = new CitrateClient({ rpcUrl: 'http://127.0.0.1:8545', privateKey: OWNER });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (client as any).keyManager = undefined;
    await expect(client.deployModel(MODEL, cfg)).rejects.toThrow(/no private key\/KeyManager is configured — refusing to upload the model in plaintext/);
  });
  it('a missing receipt fails; deploymentTime is epoch seconds', async () => {
    const client = new CitrateClient({ rpcUrl: 'http://127.0.0.1:8545', privateKey: OWNER });
    let receipt: unknown = null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (client as any).wallet.sendTransaction = async () => ({ hash: '0x' + 'ab'.repeat(32), wait: async () => receipt });
    await expect(client.deployModel(MODEL, { ...cfg, encrypted: false })).rejects.toThrow(/Transaction failed/);
    receipt = { logs: [{ topics: [ethers.id('ModelDeployed(bytes32,address)')], data: '0x' + 'ab'.repeat(64) }], gasUsed: 1n };
    const before = Math.floor(Date.now() / 1000);
    const dep = await client.deployModel(MODEL, { ...cfg, encrypted: false });
    expect(dep.deploymentTime).toBeGreaterThanOrEqual(before);
    expect(dep.deploymentTime).toBeLessThanOrEqual(before + 5);
  });
});
