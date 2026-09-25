/**
 * Embedded smart-account wallet (DEVX-S1).
 *
 * An OIDC identity deterministically owns a counterfactual ERC-4337 smart account.
 * These helpers give a developer that address WITHOUT ever touching a private key.
 *
 * Prediction mirrors Solady `LibClone::predictDeterministicAddressERC1967` — the exact
 * scheme `CitrateWalletFactory.predictAddress` uses on-chain and the Rust `wallet-aa`
 * crate replicates. Inputs (factory + implementation) come from the federation contract
 * artifact (DEVX-S0), so they can never go stale against a reroll.
 *
 * SECURITY (see handoffs/IDENTITY_AA_ADDRESS_DRIFT_2026-07-25.md): do NOT trust the
 * authority's `/aa/address` endpoint for the address — as of 2026-07-25 the deployed
 * authority runs stale AA env and returns a WRONG address. Compute locally here, and
 * where an RPC is available, verify against the on-chain factory with
 * `verifyWalletAddressOnChain()`. The factory (the deployer) is the only ground truth.
 */
import { Contract, concat, getAddress, keccak256, toUtf8Bytes, type Provider } from 'ethers';

import { AA_ADDRESSES } from '../utils/constants';
import { FEDERATION_CONTRACT, type Hex } from '../generated/contract';

/** Solady minimal ERC-1967 clone initcode segments (implementation embedded at bytes 9..29). */
const INITCODE_PREFIX = '0x603d3d8160223d3973';
const INITCODE_SEPARATOR = '0x6009';
const INITCODE_BODY = '0x5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076';
const INITCODE_TAIL = '0xcc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3';

const ZERO = '0x0000000000000000000000000000000000000000';

export class WalletPredictionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WalletPredictionError';
  }
}

/** A 0x-prefixed 32-byte hex user id (the raw stable identifier the factory salts with). */
export type UserId = Hex;

/**
 * Derive the raw 32-byte AA userId from an OIDC subject UUID.
 * Matches the authority's `wallet-claims.ts`: `keccak256(utf8(lowercase(uuid)))`.
 * For a wallet-bound (SIWE) subject, the userId is the 20-byte address left-padded to 32
 * bytes instead — use `addressToUserId` for that shape.
 */
export function uuidToUserId(uuid: string): UserId {
  return keccak256(toUtf8Bytes(uuid.toLowerCase())) as UserId;
}

/** Left-pad a 20-byte EOA address to a 32-byte AA userId (SIWE-keyed principals). */
export function addressToUserId(address: string): UserId {
  const a = getAddress(address).slice(2).toLowerCase();
  return ('0x' + '00'.repeat(12) + a) as UserId;
}

function assertUserId(userId: string): asserts userId is UserId {
  if (!/^0x[0-9a-fA-F]{64}$/.test(userId)) {
    throw new WalletPredictionError('userId must be a 0x-prefixed 32-byte hex string');
  }
}

/** keccak256(initCode) for the minimal ERC-1967 clone with `implementation` embedded. */
function erc1967InitCodeHash(implementation: string): string {
  if (getAddress(implementation) === ZERO) {
    throw new WalletPredictionError('implementation cannot be the zero address');
  }
  const impl = getAddress(implementation).toLowerCase();
  return keccak256(concat([INITCODE_PREFIX, impl, INITCODE_SEPARATOR, INITCODE_BODY, INITCODE_TAIL]));
}

export interface PredictOptions {
  /** Override the factory (defaults to the artifact's CitrateWalletFactory). */
  factory?: string;
  /** Override the implementation (defaults to the artifact's CitrateWallet = factory.implementation()). */
  implementation?: string;
}

export interface VerifyOnChainOptions extends PredictOptions {
  /** Chain the provider must report (defaults to the federation artifact chain, 40204). */
  chainId?: number;
}

/**
 * Predict the counterfactual smart-wallet address for a userId. Pure + offline.
 * `address = keccak256(0xff || factory || keccak256(userId) || keccak256(initCode))[12..32]`.
 */
export function predictWalletAddress(userId: string, opts: PredictOptions = {}): Hex {
  assertUserId(userId);
  const factory = getAddress(opts.factory ?? AA_ADDRESSES.CitrateWalletFactory);
  const implementation = opts.implementation ?? AA_ADDRESSES.CitrateWallet;
  if (factory === ZERO) throw new WalletPredictionError('factory cannot be the zero address');

  const salt = keccak256(userId);
  const initCodeHash = erc1967InitCodeHash(implementation);
  const packed = concat(['0xff', factory, salt, initCodeHash]);
  return getAddress('0x' + keccak256(packed).slice(-40)) as Hex;
}

const FACTORY_ABI = ['function predictAddress(bytes32 userId) view returns (address)'];

/**
 * Verify the locally-predicted address against the on-chain factory (ground truth).
 * The factory is the deployer, so its own `predictAddress` view is authoritative — this is
 * the check that would have caught the 2026-07-25 stale-authority bug. Returns the address
 * on match; throws if the chain disagrees with the local computation.
 */
export async function verifyWalletAddressOnChain(
  userId: string,
  provider: Provider,
  opts: VerifyOnChainOptions = {},
): Promise<Hex> {
  const local = predictWalletAddress(userId, opts);
  const factoryAddress = getAddress(opts.factory ?? AA_ADDRESSES.CitrateWalletFactory);
  // PBA-L6b-027 (variant of the Python finding): the provider is only as good
  // as the chain it is on. Assert the chain id and that the factory has code
  // before trusting its answer, so a wrong-chain or hostile RPC cannot make
  // "verified" pass by echoing the publicly computable prediction.
  const expectedChain = BigInt(opts.chainId ?? FEDERATION_CONTRACT.chain.chainId);
  const { chainId } = await provider.getNetwork();
  if (chainId !== expectedChain) {
    throw new WalletPredictionError(`provider is on chain ${chainId}, expected chain ${expectedChain} — refusing to verify`);
  }
  const code = await provider.getCode(factoryAddress);
  if (!code || code === '0x' || code === '0x0') {
    throw new WalletPredictionError(`factory ${factoryAddress} has no code on chain ${expectedChain} — refusing to verify`);
  }
  const factory = new Contract(factoryAddress, FACTORY_ABI, provider);
  const onchain = getAddress(await factory.predictAddress!(userId));
  if (onchain !== local) {
    throw new WalletPredictionError(
      `wallet address mismatch: local ${local} != on-chain factory ${onchain} — ` +
        'do not fund this address; the factory/implementation inputs are wrong',
    );
  }
  return local as Hex;
}
