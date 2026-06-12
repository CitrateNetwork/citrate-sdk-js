/**
 * Offline smart-wallet address prediction (EW-S1 WP-7).
 *
 * Mirrors — byte-for-byte — the three sibling implementations:
 *   - on-chain   `CitrateWalletFactory.predictAddress(bytes32)` (Solady
 *     `LibClone.predictDeterministicAddressERC1967`)
 *   - identity   `citrate-identity/src/aa/predict.ts` (viem)
 *   - Rust       `citrate-chain/wallet-aa/src/address.rs`
 *
 * Data source for the pinned test vectors: the LIVE factory on chain
 * 40204 (`0xd951…FD57`, `predictAddress` via eth_call) — see
 * `tests/unit/aa_address.test.ts`.
 */

import {
  getAddress,
  keccak256,
  solidityPacked,
  toUtf8Bytes,
} from 'ethers';

import type { Address, Hex } from './types';

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

/** Canonical lowercase UUID (the shape citrate-identity `users.id` takes). */
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class AddressPredictionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AddressPredictionError';
  }
}

/**
 * Map a Citrate user UUID to the 32-byte AA userId the wallet factory
 * is salted with: `keccak256(utf8(lowercase uuid))`.
 *
 * MUST stay identical to `citrate-identity/src/aa/wallet-claims.ts`
 * `uuidToUserId` — this is the cross-surface seam that makes "one
 * wallet address per user" true on every device.
 */
export function uuidToUserId(uuid: string): Hex {
  const canonical = uuid.trim().toLowerCase();
  if (!UUID_RE.test(canonical)) {
    throw new AddressPredictionError(`not a canonical UUID: ${uuid}`);
  }
  return keccak256(toUtf8Bytes(canonical)) as Hex;
}

/**
 * Resolve any Citrate OIDC accountId shape to the 32-byte AA userId:
 * 32-byte hex unchanged; 20-byte EOA left-zero-padded (degenerate SIWE
 * form); UUID via {@link uuidToUserId}; anything else → null.
 */
export function accountIdToAaUserId(accountId: string): Hex | null {
  if (typeof accountId !== 'string') return null;
  if (accountId.startsWith('0x') && accountId.length === 66) {
    return accountId as Hex;
  }
  if (accountId.startsWith('0x') && accountId.length === 42) {
    return ('0x' + accountId.slice(2).padStart(64, '0')) as Hex;
  }
  if (UUID_RE.test(accountId.trim().toLowerCase())) {
    return uuidToUserId(accountId);
  }
  return null;
}

/**
 * Predict the CREATE2 address `CitrateWalletFactory` deploys the user's
 * Kernel proxy to. `salt = keccak256(userId)`; init code is Solady's
 * 95-byte minimal ERC-1967 proxy with the implementation embedded.
 */
export function predictWalletAddress(
  factory: Address,
  implementation: Address,
  userId: Hex,
): Address {
  if (factory === ZERO_ADDRESS) {
    throw new AddressPredictionError('factory cannot be the zero address');
  }
  if (implementation === ZERO_ADDRESS) {
    throw new AddressPredictionError('implementation cannot be the zero address');
  }
  if (!userId.startsWith('0x') || userId.length !== 66) {
    throw new AddressPredictionError(
      `userId must be a 0x-prefixed 32-byte hex string (got length ${userId.length})`,
    );
  }

  const salt = keccak256(userId);
  const initCodeHash = erc1967MinimalInitCodeHash(implementation);

  // CREATE2: keccak256(0xff ++ factory ++ salt ++ initCodeHash)[12..]
  const packed = solidityPacked(
    ['bytes1', 'address', 'bytes32', 'bytes32'],
    ['0xff', factory, salt, initCodeHash],
  );
  const hash = keccak256(packed);
  return getAddress(`0x${hash.slice(-40)}`) as Address;
}

/**
 * keccak256 of Solady's minimal ERC-1967 clone init code (95 bytes)
 * with the implementation address embedded at bytes 9..29. The byte
 * layout is pinned to upstream `LibClone` — identical constants in the
 * identity-TS and Rust counterparts.
 */
export function erc1967MinimalInitCodeHash(implementation: Address): Hex {
  const impl = implementation.slice(2).toLowerCase();
  if (impl.length !== 40) {
    throw new AddressPredictionError(
      `implementation address must be 20 bytes (got ${impl.length / 2})`,
    );
  }
  const prefix = '603d3d8160223d3973';
  const separator = '6009';
  const body =
    '5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076';
  const tail =
    'cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3';

  const initCode = `0x${prefix}${impl}${separator}${body}${tail}`;
  if (initCode.length !== 2 + 95 * 2) {
    throw new AddressPredictionError(
      `init code length mismatch: ${initCode.length} chars (expected ${2 + 95 * 2})`,
    );
  }
  return keccak256(initCode) as Hex;
}
