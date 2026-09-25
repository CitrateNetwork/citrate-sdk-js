/**
 * Follow-ups from the R2 verifier on the merged PBA-L4-001 / PBA-L3a-011 fixes.
 *
 * 1. Holder dedupe must run on canonical keys. The verifier's mutant (dedupe on
 *    the raw strings) survived all 308 tests; the same holder given compressed
 *    and uncompressed (or with and without 0x) must be refused.
 * 2. `thresholdShares: NaN` silently disabled sharing; it now raises, like any
 *    other non-integer.
 * 3. threshold 1 (any single holder recovers the key) needs an explicit
 *    `allowSingleHolderRecovery: true`.
 * 4. The deploy guard also refuses share-shaped values, not only known names.
 * 5. `verifyIdToken` refuses an `iat` in the future beyond the clock tolerance.
 */
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { ethers } from 'ethers';
import { CitrateClient } from '../../src/client/CitrateClient';
import { KeyManager } from '../../src/crypto/KeyManager';
import { assertNoKeyShareMaterial } from '../../src/crypto/shareGuard';
import { splitSecretBytes } from '../../src/crypto/FiniteField';
import { verifyIdToken, type Jwk } from '../../src/identity/jwt';
import { AccessType, EncryptionConfig, ModelConfig, ModelType } from '../../src/types/Model';

const OWNER = '0x' + '11'.repeat(32);
const H = ['22', '33', '44'].map((b) => new KeyManager('0x' + b.repeat(32)));
const MODEL = new TextEncoder().encode('m');
const cfg = (extra: Partial<EncryptionConfig>): EncryptionConfig => ({
  algorithm: 'AES-256-GCM',
  keyDerivation: 'HKDF-SHA256',
  accessControl: true,
  thresholdShares: 2,
  totalShares: 3,
  ...extra,
});
const compressed = (km: KeyManager) => ethers.SigningKey.computePublicKey('0x' + km.getPublicKey(), true).slice(2);

describe('canonical holder dedupe', () => {
  it('refuses the same holder given compressed and uncompressed', async () => {
    const pubs = [H[0]!.getPublicKey(), compressed(H[0]!), H[1]!.getPublicKey()];
    expect(pubs[0]).not.toBe(pubs[1]);
    await expect(new KeyManager(OWNER).encryptModel(MODEL, cfg({ shareHolderPublicKeys: pubs }))).rejects.toThrow(/distinct/);
  });
  it('refuses the same holder with and without 0x', async () => {
    const pubs = [H[0]!.getPublicKey(), '0x' + H[0]!.getPublicKey(), H[1]!.getPublicKey()];
    await expect(new KeyManager(OWNER).encryptModel(MODEL, cfg({ shareHolderPublicKeys: pubs }))).rejects.toThrow(/distinct/);
  });
  it('accepts distinct holders in mixed encodings', async () => {
    const pubs = [compressed(H[0]!), H[1]!.getPublicKey(), '0x' + H[2]!.getPublicKey()];
    const r = await new KeyManager(OWNER).encryptModel(MODEL, cfg({ shareHolderPublicKeys: pubs }));
    expect(new Set(r.keyShareEnvelopes!.map((e) => e.holderPublicKey)).size).toBe(3);
  });
});

describe('share parameters fail closed', () => {
  const pubs = () => H.map((h) => h.getPublicKey());
  it.each([NaN, Infinity, -Infinity, 1.5])('thresholdShares %p raises', async (t) => {
    await expect(
      new KeyManager(OWNER).encryptModel(MODEL, cfg({ thresholdShares: t, shareHolderPublicKeys: pubs() })),
    ).rejects.toThrow(/invalid share parameters/);
  });
  it('threshold 0 still means "no sharing"', async () => {
    const r = await new KeyManager(OWNER).encryptModel(MODEL, cfg({ thresholdShares: 0, totalShares: 0 }));
    expect(r.keyShareEnvelopes).toBeUndefined();
  });
  it('threshold 1 is refused without the explicit opt-in', async () => {
    await expect(
      new KeyManager(OWNER).encryptModel(MODEL, cfg({ thresholdShares: 1, shareHolderPublicKeys: pubs() })),
    ).rejects.toThrow(/thresholdShares=1 lets ANY single holder recover the model key.*allowSingleHolderRecovery: true/);
  });
  it('threshold 1 with the opt-in', async () => {
    const r = await new KeyManager(OWNER).encryptModel(
      MODEL, cfg({ thresholdShares: 1, shareHolderPublicKeys: pubs(), allowSingleHolderRecovery: true }));
    expect(r.metadata.keySharing).toEqual({ threshold: 1, totalShares: 3 });
  });
});

describe('structural share guard', () => {
  const shares = splitSecretBytes(new Uint8Array(32).fill(7), 2, 3).map(({ x, y }) => ({
    x: String(x), y: Buffer.from(y).toString('hex'),
  }));
  it.each([
    [{ myShares: shares }],
    [{ a: [{ x: 1, y: 'ab12' }] }],
    [{ a: { x: '1', y: '0xab' } }],
    [{ blob: JSON.stringify({ parts: shares }) }],
    [{ blob: JSON.stringify([{ x: 2, y: 'cd' }]) }],
    [{ w: { holderPublicKey: '02' + '11'.repeat(32), envelope: '{}' } }],
    [{ w: [{ holder_public_key: '02' + '11'.repeat(32), envelope: '{}' }] }],
    [{ y: { x: 1, y: new Uint8Array([1]) } }],
    [{ padded: '  {"x": 1, "y": "ab"}  ' }],
    [{ big: JSON.stringify({ pad: 'a'.repeat(1_100_000), s: { x: 1, y: 'ab' } }) }],
  ])('refuses share-shaped case %#', (meta) => {
    expect(() => assertNoKeyShareMaterial(meta)).toThrow(
      /refusing to publish a value shaped like a key share \(\{x, y\} or a wrapped share record\) in public deploy calldata\. Deliver key shares to their holders off-chain/,
    );
  });
  it('JSON-in-string nesting counts toward the depth limit', () => {
    let v: unknown = { leaf: 1 };
    for (let i = 0; i < 20; i++) v = JSON.stringify({ n: v });
    expect(() => assertNoKeyShareMaterial({ v })).toThrow(/nested more than 32 levels/);
  });
  it.each([
    [{ x: 1, y: 2 }], [{ x: 1, y: 'not hex' }], [{ point: { x: 1 } }], [{ blob: '{not json' }],
    [{ envelope: 'e' }], [{ text: '[1, 2, 3]' }], [{ x: 1, y: 'zz12' }], [{ x: 1, y: '12zz' }], [{ n: '123' }],
  ])('allows %j', (meta) => {
    expect(() => assertNoKeyShareMaterial(meta)).not.toThrow();
  });
  it('deployModel refuses a renamed share field before sending', async () => {
    const client = new CitrateClient({ rpcUrl: 'http://127.0.0.1:8545', privateKey: OWNER });
    const send = jest.fn();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (client as any).wallet.sendTransaction = send;
    const c: ModelConfig = {
      name: 'm', modelType: ModelType.ONNX, accessType: AccessType.PUBLIC, accessPrice: 0n, encrypted: false,
      metadata: { myShares: shares },
    };
    await expect(client.deployModel(MODEL, c)).rejects.toThrow(/key share/);
    expect(send).not.toHaveBeenCalled();
  });
  it('real encrypted-deploy metadata does not trip it', async () => {
    const r = await new KeyManager(OWNER).encryptModel(MODEL, cfg({ shareHolderPublicKeys: H.map((h) => h.getPublicKey()) }));
    expect(() => assertNoKeyShareMaterial({ metadata: { encryption: r.metadata } })).not.toThrow();
  });
});

describe('verifyIdToken refuses a future iat', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const JWKS: Jwk[] = [{ ...(publicKey.export({ format: 'jwk' }) as Jwk), kid: 'k' }];
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const tok = (p: Record<string, unknown>) => {
    const input = `${b64({ alg: 'RS256', kid: 'k' })}.${b64(p)}`;
    return `${input}.${cryptoSign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
  };
  const now = 1_900_000_000;
  const opts = { issuer: 'https://i', audience: 'a', jwks: JWKS, now: now * 1000 };
  const p = (iat: number) => ({ iss: 'https://i', aud: 'a', sub: 'u', iat, exp: now + 3600 });
  it('accepts iat up to the clock tolerance ahead', () => {
    expect(verifyIdToken(tok(p(now + 60)), opts).sub).toBe('u');
  });
  it('refuses iat beyond the tolerance', () => {
    expect(() => verifyIdToken(tok(p(now + 61)), opts)).toThrow(/issued in the future/);
    expect(() => verifyIdToken(tok(p(now + 86400 * 365)), opts)).toThrow(/issued in the future/);
  });
});
