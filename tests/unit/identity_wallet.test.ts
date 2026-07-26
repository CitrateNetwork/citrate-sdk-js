/**
 * DEVX-S1 / F2 — embedded smart-account wallet prediction.
 *
 * The pinned address is EARNED against ground truth: the on-chain
 * CitrateWalletFactory.predictAddress(0x4242…) returned 0x1615Af12… on 2026-07-25
 * (rpc.citrate.ai, chain 40204). The SDK's local computation must match it byte-for-byte
 * (risk R-2). NB the authority's /aa/address returned a DIFFERENT (wrong) address that day —
 * see handoffs/IDENTITY_AA_ADDRESS_DRIFT_2026-07-25.md — which is exactly why the SDK computes
 * locally and verifies against the factory, never against the service.
 */
import {
  addressToUserId,
  predictWalletAddress,
  uuidToUserId,
  WalletPredictionError,
} from '../../src/identity/wallet';
import { AA_ADDRESSES } from '../../src/utils/constants';

const USER_ID_4242 = ('0x' + '42'.repeat(32)) as `0x${string}`;

describe('predictWalletAddress — parity with the on-chain factory', () => {
  it('matches CitrateWalletFactory.predictAddress for the pinned userId', () => {
    // On-chain ground truth (cast call factory predictAddress) 2026-07-25.
    expect(predictWalletAddress(USER_ID_4242)).toBe('0x1615Af127952c4e4987D7b597bDD7cb8B49aFB89');
  });

  it('uses the artifact factory + implementation by default (never a hand-pinned address)', () => {
    // The default implementation is the factory's on-chain implementation() = CitrateWallet.
    const explicit = predictWalletAddress(USER_ID_4242, {
      factory: AA_ADDRESSES.CitrateWalletFactory,
      implementation: AA_ADDRESSES.CitrateWallet,
    });
    expect(explicit).toBe(predictWalletAddress(USER_ID_4242));
  });

  it('is deterministic and differs across userIds', () => {
    const a = predictWalletAddress(('0x' + '01'.repeat(32)) as `0x${string}`);
    const b = predictWalletAddress(('0x' + '02'.repeat(32)) as `0x${string}`);
    expect(a).not.toBe(b);
    expect(predictWalletAddress(('0x' + '01'.repeat(32)) as `0x${string}`)).toBe(a);
  });

  it('rejects a malformed userId', () => {
    expect(() => predictWalletAddress('0xdeadbeef')).toThrow(WalletPredictionError);
  });
});

describe('userId derivation', () => {
  it('uuidToUserId = keccak256(utf8(lowercase uuid)) and is case-insensitive', () => {
    const upper = uuidToUserId('DEADBEEF-0000-4000-8000-000000000000');
    const lower = uuidToUserId('deadbeef-0000-4000-8000-000000000000');
    expect(upper).toBe(lower);
    expect(upper).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('addressToUserId left-pads a 20-byte EOA to 32 bytes', () => {
    const uid = addressToUserId('0x000000000000000000000000000000000000dEaD');
    expect(uid).toBe('0x000000000000000000000000000000000000000000000000000000000000dead');
  });
});
