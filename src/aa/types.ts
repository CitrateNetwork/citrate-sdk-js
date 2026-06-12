/**
 * ERC-4337 v0.7 types for the Citrate embedded-wallet stack (EW-S1 WP-7).
 *
 * Two representations exist on purpose:
 *
 *  - {@link PackedUserOperation} — the on-chain struct EntryPoint v0.7
 *    hashes and validates (gas fields packed into two bytes32 words).
 *    This is what `getUserOpHash` is computed over and what validator
 *    contracts see.
 *  - {@link RpcUserOperation} — the UNPACKED wire shape the
 *    eth-infinitism bundler's `eth_sendUserOperation` expects (every
 *    field its own hex quantity; factory/paymaster split out).
 *
 * Conversions live in `userop.ts`.
 */

/** 0x-prefixed hex string. */
export type Hex = `0x${string}`;

/** 20-byte 0x-prefixed address. */
export type Address = `0x${string}`;

/** The on-chain EntryPoint v0.7 PackedUserOperation struct. */
export interface PackedUserOperation {
  sender: Address;
  nonce: bigint;
  /** `factory address ++ factoryData`, or '0x' when already deployed. */
  initCode: Hex;
  callData: Hex;
  /** `verificationGasLimit (16 bytes) ++ callGasLimit (16 bytes)`. */
  accountGasLimits: Hex;
  preVerificationGas: bigint;
  /** `maxPriorityFeePerGas (16 bytes) ++ maxFeePerGas (16 bytes)`. */
  gasFees: Hex;
  /** `paymaster (20) ++ pmVerificationGasLimit (16) ++ pmPostOpGasLimit (16) ++ pmData`, or '0x'. */
  paymasterAndData: Hex;
  signature: Hex;
}

/** Unpacked v0.7 wire format for the bundler JSON-RPC surface. */
export interface RpcUserOperation {
  sender: Address;
  nonce: Hex;
  factory?: Address;
  factoryData?: Hex;
  callData: Hex;
  callGasLimit: Hex;
  verificationGasLimit: Hex;
  preVerificationGas: Hex;
  maxFeePerGas: Hex;
  maxPriorityFeePerGas: Hex;
  paymaster?: Address;
  paymasterVerificationGasLimit?: Hex;
  paymasterPostOpGasLimit?: Hex;
  paymasterData?: Hex;
  signature: Hex;
}

/**
 * CitratePaymaster sponsorship categories. Encoded as the single byte
 * at offset 52 of `paymasterAndData` (right after the two packed
 * paymaster gas limits) — see
 * `citrate-chain/contracts/src/aa/paymaster/CitratePaymaster.sol`
 * (`PMD_TAG_OFFSET = 52`).
 */
export enum PaymasterCategory {
  /** Counts against the per-user daily cap. */
  Standard = 0,
  /** Guardian-recovery ops; per-event budget, never rate-limited away. */
  Recovery = 1,
  /** The account's first sponsored op (wallet deploy); one per account. */
  FirstOp = 2,
}

/**
 * The deployed Citrate AA stack on one chain. Canonical source:
 * `citrate-chain/contracts/addresses/40204.json` → `aaStack`, also
 * served by `auth.citrate.ai` (see `/aa/*`).
 */
export interface CitrateAaConfig {
  chainId: bigint;
  entryPoint: Address;
  factory: Address;
  /** The CitrateWallet (Kernel v3) implementation behind every proxy. */
  walletImpl: Address;
  paymaster: Address;
  webauthnValidator: Address;
  ecdsaValidator: Address;
  guardianRecoveryModule: Address;
}

/** Receipt shape returned by `eth_getUserOperationReceipt` (subset we rely on). */
export interface UserOperationReceipt {
  userOpHash: Hex;
  sender: Address;
  nonce: Hex;
  success: boolean;
  actualGasCost: Hex;
  actualGasUsed: Hex;
  receipt: {
    transactionHash: Hex;
    blockNumber: Hex;
    [k: string]: unknown;
  };
  [k: string]: unknown;
}
