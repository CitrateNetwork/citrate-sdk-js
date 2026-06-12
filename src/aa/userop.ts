/**
 * ERC-4337 v0.7 UserOperation construction (EW-S1 WP-7).
 *
 * Pure functions only — chain reads (nonce, deploy status) are taken
 * as inputs so the same builder runs in the browser (against
 * auth.citrate.ai + the bundler) and in tests (against pinned
 * vectors). The hash implementation is verified against the LIVE
 * EntryPoint v0.7 on chain 40204 (`getUserOpHash` via eth_call) in
 * `tests/unit/aa_userop.test.ts`.
 */

import { AbiCoder, FunctionFragment, concat, keccak256, toBeHex, zeroPadValue } from 'ethers';

import type {
  Address,
  Hex,
  PackedUserOperation,
  RpcUserOperation,
} from './types';
import { PaymasterCategory } from './types';

const coder = AbiCoder.defaultAbiCoder();

export class UserOpError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UserOpError';
  }
}

// ── packing helpers ───────────────────────────────────────────────────

/** Pack two 128-bit quantities into one bytes32 (`hi ++ lo`). */
export function packUint128Pair(hi: bigint, lo: bigint): Hex {
  if (hi < 0n || hi >= 1n << 128n || lo < 0n || lo >= 1n << 128n) {
    throw new UserOpError('packed halves must fit in 128 bits');
  }
  return concat([
    zeroPadValue(toBeHex(hi), 16),
    zeroPadValue(toBeHex(lo), 16),
  ]) as Hex;
}

/** `accountGasLimits = verificationGasLimit ++ callGasLimit`. */
export function packAccountGasLimits(
  verificationGasLimit: bigint,
  callGasLimit: bigint,
): Hex {
  return packUint128Pair(verificationGasLimit, callGasLimit);
}

/** `gasFees = maxPriorityFeePerGas ++ maxFeePerGas`. */
export function packGasFees(
  maxPriorityFeePerGas: bigint,
  maxFeePerGas: bigint,
): Hex {
  return packUint128Pair(maxPriorityFeePerGas, maxFeePerGas);
}

/**
 * `paymasterAndData` for the CitratePaymaster:
 * `paymaster(20) ++ pmVerificationGasLimit(16) ++ pmPostOpGasLimit(16)
 *  ++ category(1)` — the category byte sits at offset 52, exactly
 * where the contract's `PMD_TAG_OFFSET` reads it.
 */
export function packCitratePaymasterAndData(args: {
  paymaster: Address;
  paymasterVerificationGasLimit: bigint;
  paymasterPostOpGasLimit: bigint;
  category: PaymasterCategory;
}): Hex {
  return concat([
    args.paymaster,
    zeroPadValue(toBeHex(args.paymasterVerificationGasLimit), 16),
    zeroPadValue(toBeHex(args.paymasterPostOpGasLimit), 16),
    new Uint8Array([args.category]),
  ]) as Hex;
}

// ── factory initCode ─────────────────────────────────────────────────

/**
 * Calldata for `CitrateWalletFactory.deployFor(bytes32,address,bytes,uint256,bytes)`.
 * The permit `signature` comes from `auth.citrate.ai`'s
 * `POST /aa/enroll-validator` (the identity signer's EIP-191 over the
 * factory's `permitDigest`).
 */
export function encodeDeployFor(args: {
  userId: Hex;
  initialValidator: Address;
  initData: Hex;
  expiresAt: bigint;
  signature: Hex;
}): Hex {
  const frag = FunctionFragment.from(
    'deployFor(bytes32 userId, address initialValidator, bytes initData, uint256 expiresAt, bytes signature)',
  );
  return concat([
    frag.selector,
    coder.encode(
      ['bytes32', 'address', 'bytes', 'uint256', 'bytes'],
      [args.userId, args.initialValidator, args.initData, args.expiresAt, args.signature],
    ),
  ]) as Hex;
}

/** v0.7 `initCode = factory address ++ factoryData`. */
export function packInitCode(factory: Address, factoryData: Hex): Hex {
  return concat([factory, factoryData]) as Hex;
}

// ── build + hash ──────────────────────────────────────────────────────

export interface BuildUserOpArgs {
  sender: Address;
  /** Full 256-bit nonce (use kernel.ts composeNonce / EntryPoint.getNonce). */
  nonce: bigint;
  /** '0x' when the wallet is already deployed. */
  initCode?: Hex;
  callData: Hex;
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  preVerificationGas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  /** '0x' for self-paid ops. Use packCitratePaymasterAndData for sponsored ones. */
  paymasterAndData?: Hex;
  signature?: Hex;
}

/** Assemble a PackedUserOperation from unpacked inputs. */
export function buildPackedUserOp(args: BuildUserOpArgs): PackedUserOperation {
  return {
    sender: args.sender,
    nonce: args.nonce,
    initCode: args.initCode ?? '0x',
    callData: args.callData,
    accountGasLimits: packAccountGasLimits(
      args.verificationGasLimit,
      args.callGasLimit,
    ),
    preVerificationGas: args.preVerificationGas,
    gasFees: packGasFees(args.maxPriorityFeePerGas, args.maxFeePerGas),
    paymasterAndData: args.paymasterAndData ?? '0x',
    signature: args.signature ?? '0x',
  };
}

/**
 * EntryPoint v0.7 `getUserOpHash`: keccak256(abi.encode(innerHash,
 * entryPoint, chainId)) where innerHash commits to every field with
 * the dynamic ones pre-hashed. Verified against the live EntryPoint
 * on 40204 (pinned vector in the unit tests).
 */
export function getUserOpHash(
  op: PackedUserOperation,
  entryPoint: Address,
  chainId: bigint,
): Hex {
  const inner = keccak256(
    coder.encode(
      [
        'address',
        'uint256',
        'bytes32',
        'bytes32',
        'bytes32',
        'uint256',
        'bytes32',
        'bytes32',
      ],
      [
        op.sender,
        op.nonce,
        keccak256(op.initCode),
        keccak256(op.callData),
        op.accountGasLimits,
        op.preVerificationGas,
        op.gasFees,
        keccak256(op.paymasterAndData),
      ],
    ),
  );
  return keccak256(
    coder.encode(['bytes32', 'address', 'uint256'], [inner, entryPoint, chainId]),
  ) as Hex;
}

// ── packed ↔ RPC (bundler wire) conversion ───────────────────────────

function hexQuantity(v: bigint): Hex {
  return toBeHex(v) as Hex;
}

function splitUint128Pair(word: Hex): { hi: bigint; lo: bigint } {
  if (!word.startsWith('0x') || word.length !== 66) {
    throw new UserOpError('expected a bytes32 hex word');
  }
  return {
    hi: BigInt('0x' + word.slice(2, 34)),
    lo: BigInt('0x' + word.slice(34, 66)),
  };
}

/**
 * Convert a PackedUserOperation to the UNPACKED v0.7 wire format the
 * eth-infinitism bundler's `eth_sendUserOperation` expects.
 */
export function toRpcUserOperation(op: PackedUserOperation): RpcUserOperation {
  const gas = splitUint128Pair(op.accountGasLimits);
  const fees = splitUint128Pair(op.gasFees);

  const rpc: RpcUserOperation = {
    sender: op.sender,
    nonce: hexQuantity(op.nonce),
    callData: op.callData,
    callGasLimit: hexQuantity(gas.lo),
    verificationGasLimit: hexQuantity(gas.hi),
    preVerificationGas: hexQuantity(op.preVerificationGas),
    maxPriorityFeePerGas: hexQuantity(fees.hi),
    maxFeePerGas: hexQuantity(fees.lo),
    signature: op.signature,
  };

  if (op.initCode !== '0x' && op.initCode.length >= 42) {
    rpc.factory = ('0x' + op.initCode.slice(2, 42)) as Address;
    rpc.factoryData = ('0x' + op.initCode.slice(42)) as Hex;
  }

  if (op.paymasterAndData !== '0x') {
    if (op.paymasterAndData.length < 2 + 52 * 2) {
      throw new UserOpError(
        'paymasterAndData must carry paymaster + two 16-byte gas limits',
      );
    }
    const pmd = op.paymasterAndData.slice(2);
    rpc.paymaster = ('0x' + pmd.slice(0, 40)) as Address;
    rpc.paymasterVerificationGasLimit = hexQuantity(BigInt('0x' + pmd.slice(40, 72)));
    rpc.paymasterPostOpGasLimit = hexQuantity(BigInt('0x' + pmd.slice(72, 104)));
    rpc.paymasterData = ('0x' + pmd.slice(104)) as Hex;
  }

  return rpc;
}
