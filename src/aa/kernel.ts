/**
 * Kernel v3 (ERC-7579) encoding helpers (EW-S1 WP-7).
 *
 * Everything here is pinned to the vendored Kernel v3.3 sources in
 * `citrate-chain/contracts/lib/kernel/`:
 *
 *  - Nonce layout (`ValidationTypeLib.decodeNonce`):
 *      1B mode | 1B vType | 20B validator | 2B nonceKey | 8B sequence
 *  - `execute(bytes32 execMode, bytes executionCalldata)` — single
 *    call packs `target ++ value ++ data`; batch ABI-encodes
 *    `(address,uint256,bytes)[]`.
 *  - `initialize(bytes21,address,bytes,bytes,bytes[])` — the factory
 *    `initData`; mirrors `citrate-identity/src/aa/install-data.ts` and
 *    `citrate-chain/wallet-aa/src/init_data.rs`.
 */

import { AbiCoder, FunctionFragment, concat, solidityPacked } from 'ethers';

import type { Address, Hex } from './types';

const coder = AbiCoder.defaultAbiCoder();

export class KernelEncodingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KernelEncodingError';
  }
}

// ── Validation types (Kernel `types/Constants.sol`) ──────────────────

export const VALIDATION_MODE_DEFAULT = 0x00;
export const VALIDATION_TYPE_ROOT = 0x00;
export const VALIDATION_TYPE_VALIDATOR = 0x01;

/**
 * Build the 256-bit EntryPoint nonce that routes validation to the
 * account's ROOT validator (mode, type, identifier all zero). The
 * 8-byte sequence comes from `EntryPoint.getNonce(sender, key)`.
 */
export function rootValidatorNonce(sequence: bigint): bigint {
  if (sequence < 0n || sequence >= 1n << 64n) {
    throw new KernelEncodingError('sequence must fit in 64 bits');
  }
  return sequence;
}

/**
 * The 192-bit EntryPoint nonce KEY that routes validation to an
 * installed (non-root) validator:
 * `0x00 | 0x01 | validator(20B) | nonceKey(2B)` per Kernel's
 * `decodeNonce`. Pass to `EntryPoint.getNonce(sender, key)`; the
 * EntryPoint appends the 8-byte sequence itself.
 */
export function validatorNonceKey(validator: Address, nonceKey = 0): bigint {
  const addr = validator.slice(2).toLowerCase();
  if (addr.length !== 40) {
    throw new KernelEncodingError('validator must be a 20-byte address');
  }
  if (nonceKey < 0 || nonceKey > 0xffff) {
    throw new KernelEncodingError('nonceKey must fit in 2 bytes');
  }
  const hex =
    '00' + // mode = VALIDATION_MODE_DEFAULT
    '01' + // vType = VALIDATION_TYPE_VALIDATOR
    addr +
    nonceKey.toString(16).padStart(4, '0');
  return BigInt('0x' + hex);
}

/** Compose a full 256-bit nonce from a 192-bit key + 64-bit sequence. */
export function composeNonce(key: bigint, sequence: bigint): bigint {
  if (key < 0n || key >= 1n << 192n) {
    throw new KernelEncodingError('nonce key must fit in 192 bits');
  }
  if (sequence < 0n || sequence >= 1n << 64n) {
    throw new KernelEncodingError('sequence must fit in 64 bits');
  }
  return (key << 64n) | sequence;
}

// ── execute() encoding ────────────────────────────────────────────────

/** `execute(bytes32,bytes)` selector — Kernel.sol line 330. */
export const EXECUTE_SELECTOR = FunctionFragment.from(
  'execute(bytes32 execMode, bytes executionCalldata)',
).selector as Hex;

const CALLTYPE_SINGLE = '0x00';
const CALLTYPE_BATCH = '0x01';

/**
 * ERC-7579 ExecMode word: callType(1) | execType(1, 0x00 = revert on
 * failure) | 4 unused | 4 modeSelector | 22 modePayload — all zero
 * after the callType for the default modes Kernel supports.
 */
function execModeWord(callType: string): Hex {
  return (callType + '00'.repeat(31)) as Hex;
}

/** One call inside a batch. */
export interface Call {
  to: Address;
  value: bigint;
  data: Hex;
}

/** Encode `execute()` calldata for a single external call. */
export function encodeExecuteSingle(call: Call): Hex {
  const packed = solidityPacked(
    ['address', 'uint256', 'bytes'],
    [call.to, call.value, call.data],
  );
  return concat([
    EXECUTE_SELECTOR,
    coder.encode(['bytes32', 'bytes'], [execModeWord(CALLTYPE_SINGLE), packed]),
  ]) as Hex;
}

/** Encode `execute()` calldata for a batch of calls. */
export function encodeExecuteBatch(calls: Call[]): Hex {
  if (calls.length === 0) {
    throw new KernelEncodingError('batch must contain at least one call');
  }
  const executions = calls.map((c) => [c.to, c.value, c.data]);
  const encoded = coder.encode(
    ['tuple(address,uint256,bytes)[]'],
    [executions],
  );
  return concat([
    EXECUTE_SELECTOR,
    coder.encode(['bytes32', 'bytes'], [execModeWord(CALLTYPE_BATCH), encoded]),
  ]) as Hex;
}

// ── Module management calldata (self-calls via execute) ─────────────

export const MODULE_TYPE_VALIDATOR = 1n;

/** `installModule(uint256,address,bytes)` calldata. */
export function encodeInstallModule(
  moduleType: bigint,
  module: Address,
  initData: Hex,
): Hex {
  const frag = FunctionFragment.from(
    'installModule(uint256 moduleType, address module, bytes initData)',
  );
  return concat([
    frag.selector,
    coder.encode(['uint256', 'address', 'bytes'], [moduleType, module, initData]),
  ]) as Hex;
}

/** `uninstallModule(uint256,address,bytes)` calldata. */
export function encodeUninstallModule(
  moduleType: bigint,
  module: Address,
  deInitData: Hex,
): Hex {
  const frag = FunctionFragment.from(
    'uninstallModule(uint256 moduleType, address module, bytes deInitData)',
  );
  return concat([
    frag.selector,
    coder.encode(['uint256', 'address', 'bytes'], [moduleType, module, deInitData]),
  ]) as Hex;
}

/** `changeRootValidator(bytes21,address,bytes,bytes)` calldata. */
export function encodeChangeRootValidator(args: {
  validator: Address;
  validationType?: number;
  hook?: Address;
  validatorData: Hex;
  hookData?: Hex;
}): Hex {
  const frag = FunctionFragment.from(
    'changeRootValidator(bytes21 rootValidator, address hook, bytes validatorData, bytes hookData)',
  );
  return concat([
    frag.selector,
    coder.encode(
      ['bytes21', 'address', 'bytes', 'bytes'],
      [
        packValidationId(args.validationType ?? VALIDATION_TYPE_VALIDATOR, args.validator),
        args.hook ?? '0x0000000000000000000000000000000000000000',
        args.validatorData,
        args.hookData ?? '0x',
      ],
    ),
  ]) as Hex;
}

// ── initialize() calldata + install-data packers ─────────────────────

/** `bytes21 ValidationId`: 1-byte type + 20-byte validator address. */
export function packValidationId(validationType: number, validator: Address): Hex {
  if (validationType < 0 || validationType > 0xff) {
    throw new KernelEncodingError('validationType must fit in a byte');
  }
  const addr = validator.slice(2);
  if (addr.length !== 40) {
    throw new KernelEncodingError('validator address must be 20 bytes');
  }
  return `0x${validationType.toString(16).padStart(2, '0')}${addr}` as Hex;
}

/**
 * `initialize(bytes21,address,bytes,bytes,bytes[])` calldata — the
 * `initData` the factory's `deployFor` executes on the fresh proxy.
 */
export function kernelInitializeCalldata(args: {
  rootValidator: Address;
  validationType?: number;
  hook?: Address;
  validatorData: Hex;
  hookData?: Hex;
  initConfig?: Hex[];
}): Hex {
  const frag = FunctionFragment.from(
    'initialize(bytes21 rootValidator, address hook, bytes validatorData, bytes hookData, bytes[] initConfig)',
  );
  return concat([
    frag.selector,
    coder.encode(
      ['bytes21', 'address', 'bytes', 'bytes', 'bytes[]'],
      [
        packValidationId(args.validationType ?? VALIDATION_TYPE_VALIDATOR, args.rootValidator),
        args.hook ?? '0x0000000000000000000000000000000000000000',
        args.validatorData,
        args.hookData ?? '0x',
        args.initConfig ?? [],
      ],
    ),
  ]) as Hex;
}

/**
 * WebAuthn validator `onInstall` payload:
 * `bytes32 credentialIdHash | uint256 x | uint256 y | uint8 requireUv`
 * (97 bytes — strict; the contract reverts on any other length).
 */
export function webauthnInstallData(args: {
  credentialIdHash: Hex;
  x: Hex;
  y: Hex;
  requireUserVerification: boolean;
}): Hex {
  expectBytes('credentialIdHash', args.credentialIdHash, 32);
  expectBytes('x', args.x, 32);
  expectBytes('y', args.y, 32);
  return concat([
    args.credentialIdHash,
    args.x,
    args.y,
    args.requireUserVerification ? '0x01' : '0x00',
  ]) as Hex;
}

/** Source enum on `CitrateECDSAValidator` — keep in sync with the contract. */
export enum EcdsaValidatorSource {
  Unknown = 0,
  GuiNative = 1,
  WalletExtension = 2,
  Other = 3,
}

/** ECDSA validator `onInstall` payload: `address owner | uint8 source` (21 bytes). */
export function ecdsaInstallData(args: {
  owner: Address;
  source: EcdsaValidatorSource;
}): Hex {
  const owner = args.owner.slice(2);
  if (owner.length !== 40) {
    throw new KernelEncodingError('owner must be a 20-byte address');
  }
  return `0x${owner}${args.source.toString(16).padStart(2, '0')}` as Hex;
}

/**
 * Guardian recovery `onInstall` payload:
 * `uint8 threshold | uint8 count | address[count]` (2 + 20·N bytes).
 * Mirrors the contract's bounds so callers get a clear local error.
 */
export function guardianInstallData(args: {
  threshold: number;
  guardians: Address[];
}): Hex {
  const count = args.guardians.length;
  if (count < 2 || count > 7) {
    throw new KernelEncodingError(`guardian count must be in [2, 7] (got ${count})`);
  }
  if (args.threshold < 1 || args.threshold > count) {
    throw new KernelEncodingError(
      `threshold must be in [1, ${count}] (got ${args.threshold})`,
    );
  }
  const seen = new Set<string>();
  let out =
    args.threshold.toString(16).padStart(2, '0') +
    count.toString(16).padStart(2, '0');
  for (const g of args.guardians) {
    const k = g.toLowerCase();
    if (seen.has(k)) throw new KernelEncodingError(`duplicate guardian: ${g}`);
    seen.add(k);
    out += g.slice(2);
  }
  return `0x${out}` as Hex;
}

// ── helpers ───────────────────────────────────────────────────────────

function expectBytes(name: string, hex: Hex, byteCount: number): void {
  if (!hex.startsWith('0x') || hex.length !== 2 + byteCount * 2) {
    throw new KernelEncodingError(
      `${name} must be a ${byteCount}-byte 0x-prefixed hex (got length ${hex.length})`,
    );
  }
}
