/**
 * Citrate embedded-wallet (ERC-4337 v0.7 / Kernel v3) helpers — EW-S1 WP-7.
 *
 * The flow a surface implements with these pieces:
 *
 *   1. `uuidToUserId(citrateUserId)` → 32-byte AA userId
 *   2. `predictWalletAddress(factory, walletImpl, userId)` → the ONE
 *      address this user has on every surface
 *   3. First op: `POST auth.citrate.ai/aa/enroll-validator` → permit;
 *      `encodeDeployFor` + `packInitCode` → `initCode`
 *   4. `encodeExecuteSingle/Batch` → callData;
 *      `EntryPoint.getNonce` + kernel nonce helpers → nonce
 *   5. `buildPackedUserOp` + `packCitratePaymasterAndData` → op;
 *      `getUserOpHash` → hash
 *   6. `signUserOpWithPasskey` (or `signUserOpWithEoa`) → signature
 *   7. `BundlerClient.sendUserOperation` → `waitForUserOperationReceipt`
 */

export * from './types';
export * from './address';
export * from './kernel';
export * from './userop';
export * from './webauthn';
export * from './eoa';
export * from './recovery';
export { BundlerClient, BundlerRpcError, CITRATE_BUNDLER_URL } from './bundler';
export type { BundlerClientOptions } from './bundler';
