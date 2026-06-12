/**
 * Guardian-recovery UserOp building (EW-S1 WP-7/WP-10).
 *
 * Per `GuardianRecoveryModule.sol`:
 *
 *  - The recovery UserOp routes validation to the module via the
 *    Kernel nonce key (validator-type 0x01 + module address).
 *  - `userOp.signature` is exactly `threshold` concatenated 65-byte
 *    ECDSA signatures over `keccak256(userOpHash ++ account)` — bound
 *    to the account so one user's recovery signatures cannot be
 *    replayed on another wallet sharing a guardian. Raw or EIP-191
 *    ("personal_sign") shapes are both accepted on-chain.
 *  - The chain only enforces M-of-N; THIS builder is what constrains
 *    the action to "rotate the signer" (the module's doc comment makes
 *    the SDK responsible for that) — the callData is pinned to
 *    Kernel's `changeRootValidator` toward a fresh WebAuthn passkey.
 */

import { concat, keccak256, solidityPacked } from 'ethers';

import type { Address, Hex } from './types';
import {
  encodeChangeRootValidator,
  encodeExecuteSingle,
  validatorNonceKey,
  webauthnInstallData,
} from './kernel';

export class RecoveryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RecoveryError';
  }
}

/**
 * The digest each guardian signs for a given recovery UserOp:
 * `keccak256(userOpHash ++ account)`. Guardians may sign it raw
 * (eth_sign-style) or via personal_sign (EIP-191) — the module
 * accepts both.
 */
export function guardianRecoveryDigest(userOpHash: Hex, account: Address): Hex {
  return keccak256(
    solidityPacked(['bytes32', 'address'], [userOpHash, account]),
  ) as Hex;
}

/**
 * Concatenate guardian signatures into the module's expected blob.
 * The module requires EXACTLY `threshold` signatures — pass that many,
 * each 65 bytes, from distinct guardians.
 */
export function packGuardianSignatures(signatures: Hex[]): Hex {
  if (signatures.length === 0) {
    throw new RecoveryError('at least one guardian signature is required');
  }
  for (const sig of signatures) {
    if (!sig.startsWith('0x') || sig.length !== 2 + 65 * 2) {
      throw new RecoveryError('each guardian signature must be 65 bytes');
    }
  }
  return concat(signatures) as Hex;
}

export interface RotateSignerArgs {
  /** The smart-wallet being recovered. */
  account: Address;
  /** The WebAuthnP256Validator address (new root validator). */
  webauthnValidator: Address;
  /** The fresh passkey to rotate to. */
  newPasskey: {
    credentialIdHash: Hex;
    x: Hex;
    y: Hex;
    requireUserVerification: boolean;
  };
}

/**
 * Build the `callData` + nonce key for the rotate-signer recovery op:
 * a self-call to Kernel's `changeRootValidator` installing the fresh
 * passkey on the WebAuthn validator, validated by the recovery module
 * (selected via the returned 192-bit nonce key).
 *
 * Flow: build → `EntryPoint.getNonce(account, nonceKey)` → compose the
 * full nonce → `getUserOpHash` → collect guardian signatures over
 * {@link guardianRecoveryDigest} → {@link packGuardianSignatures} →
 * submit via the bundler with the `Recovery` paymaster category.
 */
export function buildRotateSignerCall(
  args: RotateSignerArgs,
  guardianRecoveryModule: Address,
): { callData: Hex; nonceKey: bigint } {
  const rotateCalldata = encodeChangeRootValidator({
    validator: args.webauthnValidator,
    validatorData: webauthnInstallData(args.newPasskey),
  });
  const callData = encodeExecuteSingle({
    to: args.account,
    value: 0n,
    data: rotateCalldata,
  });
  return {
    callData,
    nonceKey: validatorNonceKey(guardianRecoveryModule),
  };
}
