/**
 * EW-S1 WP-7 — smart-wallet address prediction parity.
 *
 * Data sources (no mocks):
 *  - LIVE chain-40204 vectors captured 2026-06-11 via eth_call against
 *    the canonical factory `0xd951Cb15495cb6541F7541b9194B2D311E12FD57`
 *    (`predictAddress(bytes32)`), wallet impl
 *    `0x99b370120E7F0A4EA4F85cfcb86D4B8d41C3239b` — addresses per
 *    `citrate-chain/contracts/addresses/40204.json` → `aaStack`.
 *  - The UUID mapping is pinned to
 *    `citrate-identity/src/aa/wallet-claims.ts` (`uuidToUserId`).
 */

import { keccak256, toUtf8Bytes } from 'ethers';

import {
  accountIdToAaUserId,
  predictWalletAddress,
  uuidToUserId,
  AddressPredictionError,
} from '../../src/aa/address';

const FACTORY = '0xd951Cb15495cb6541F7541b9194B2D311E12FD57' as const;
const WALLET_IMPL = '0x99b370120E7F0A4EA4F85cfcb86D4B8d41C3239b' as const;

// cast call $FACTORY 'predictAddress(bytes32)(address)' <userId> --rpc-url https://rpc.citrate.ai
const VEC_USER_ID_1 =
  '0x1111111111111111111111111111111111111111111111111111111111111111' as const;
const VEC_ADDR_1 = '0x5cE327300221659b66323dC344C2275A7DA756fF';

// userId = keccak256(utf8("0d1f02f1-1f5a-4f5e-9c2e-7b8d1a2b3c4d"))
const VEC_UUID = '0d1f02f1-1f5a-4f5e-9c2e-7b8d1a2b3c4d';
const VEC_USER_ID_2 =
  '0x23691dc9a1d9d7ffa4787edf129321063826c584f406598e645141dba9db32d8';
const VEC_ADDR_2 = '0x05d25D894E88B288f3F7508ce6523D79DEE5DE28';

describe('uuidToUserId', () => {
  it('is keccak256 of the utf8 lowercase uuid (identity-seam parity)', () => {
    expect(uuidToUserId(VEC_UUID)).toBe(keccak256(toUtf8Bytes(VEC_UUID)));
    expect(uuidToUserId(VEC_UUID)).toBe(VEC_USER_ID_2);
  });

  it('normalizes case', () => {
    expect(uuidToUserId(VEC_UUID.toUpperCase())).toBe(uuidToUserId(VEC_UUID));
  });

  it('rejects non-uuid input', () => {
    expect(() => uuidToUserId('nope')).toThrow(AddressPredictionError);
  });
});

describe('predictWalletAddress — parity with the LIVE factory on 40204', () => {
  it('matches the on-chain prediction for a raw 32-byte userId', () => {
    expect(predictWalletAddress(FACTORY, WALLET_IMPL, VEC_USER_ID_1)).toBe(
      VEC_ADDR_1,
    );
  });

  it('matches the on-chain prediction for a UUID-derived userId', () => {
    expect(
      predictWalletAddress(FACTORY, WALLET_IMPL, uuidToUserId(VEC_UUID)),
    ).toBe(VEC_ADDR_2);
  });

  it('is deterministic and input-sensitive', () => {
    const a = predictWalletAddress(FACTORY, WALLET_IMPL, VEC_USER_ID_1);
    expect(predictWalletAddress(FACTORY, WALLET_IMPL, VEC_USER_ID_1)).toBe(a);
    expect(
      predictWalletAddress(FACTORY, WALLET_IMPL, VEC_USER_ID_2),
    ).not.toBe(a);
  });

  it('rejects zero addresses and malformed userIds', () => {
    const zero = '0x0000000000000000000000000000000000000000' as const;
    expect(() =>
      predictWalletAddress(zero, WALLET_IMPL, VEC_USER_ID_1),
    ).toThrow(AddressPredictionError);
    expect(() =>
      predictWalletAddress(FACTORY, zero, VEC_USER_ID_1),
    ).toThrow(AddressPredictionError);
    expect(() =>
      predictWalletAddress(FACTORY, WALLET_IMPL, '0x1234' as never),
    ).toThrow(AddressPredictionError);
  });
});

describe('accountIdToAaUserId — all three account shapes', () => {
  it('passes a 32-byte hex through', () => {
    expect(accountIdToAaUserId(VEC_USER_ID_1)).toBe(VEC_USER_ID_1);
  });

  it('zero-pads a 20-byte EOA', () => {
    const eoa = '0x8ba1f109551bD432803012645Ac136ddd64DBA72';
    expect(accountIdToAaUserId(eoa)).toBe(
      '0x' + eoa.slice(2).padStart(64, '0'),
    );
  });

  it('hashes UUIDs', () => {
    expect(accountIdToAaUserId(VEC_UUID)).toBe(VEC_USER_ID_2);
  });

  it('returns null otherwise', () => {
    expect(accountIdToAaUserId('garbage')).toBeNull();
  });
});
