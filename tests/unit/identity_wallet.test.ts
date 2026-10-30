/**
 * DEVX-S1 / F2 — embedded smart-account wallet prediction.
 *
 * r1006 (genesis 0xa3651a27…, book citrate-chain contracts/addresses/r1006/40204.json): the
 * factory is 0x6ee3b590…, the implementation CitrateWallet 0x2d742b98… is unchanged, and the
 * pinned vector is 0xEFf9CC17…, computed offline with the same Solady formula that reproduces
 * the r1005 live value below byte-for-byte. Re-read it from the live factory's
 * predictAddress(0x4242…) after the r1006 public cutover.
 *
 * r1005 history: the on-chain
 * CitrateWalletFactory.predictAddress(0x4242…) returned 0x6Ef76179… on 2026-10-06
 * (rpc.citrate.ai, chain 40204, genesis 0x1dcfc490…, live factory 0x9Ac05AD6…), re-verified after
 * the r1005 re-roll (citrate-chain 2979a157) retired the previous factory 0x24e2a41E… (which had
 * returned 0x79A94592… on 2026-10-04; 0xfb43484C… on 2026-09-23 and 0x1615Af12… on 2026-07-25
 * before that). The SDK computes locally
 * from the vendored federation-contract artifact's post-reroll factory + implementation, so the
 * value moves with the artifact, not with a hand-pinned constant. The local computation must
 * match the live factory byte-for-byte
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
    // r1006 factory 0x6ee3b590… (offline; the formula reproduces r1005's live 0x6Ef76179…).
    expect(predictWalletAddress(USER_ID_4242)).toBe('0xEFf9CC174Cdcbe60FF9D8D2b469Fb94008C8336D');
  });

  it('the formula reproduces the r1005 live factory answer (2026-10-06) from its inputs', () => {
    expect(
      predictWalletAddress(USER_ID_4242, {
        factory: '0x9Ac05AD65C9E8E48Fbb41dDE029512afA5346C85',
        implementation: '0x2D742B98D867Fc7363F530DD6d756622e4Eb768D',
      }),
    ).toBe('0x6Ef7617980a1fe91D3449315E8D48f99A68Bb5eA');
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
