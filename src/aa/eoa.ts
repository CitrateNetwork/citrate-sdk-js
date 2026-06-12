/**
 * EOA (secp256k1) UserOp signing for the `CitrateECDSAValidator` path
 * (EW-S1 WP-7; consumed by the gui-native + wallet-extension link
 * flows in WP-8/9).
 *
 * The validator accepts a 65-byte ECDSA signature over the userOpHash
 * in either shape: raw, or EIP-191 "personal_sign" prefixed. Browser
 * wallets emit the prefixed shape via `personal_sign`; ethers'
 * `signMessage` produces the same, so both surfaces converge here.
 */

import { getBytes, type Signer } from 'ethers';

import type { Hex } from './types';

/**
 * Sign a userOpHash with any ethers Signer (in-page wallet, keystore
 * EOA, hardware). Produces the EIP-191-prefixed shape the validator's
 * second recovery branch accepts.
 */
export async function signUserOpWithEoa(
  signer: Signer,
  userOpHash: Hex,
): Promise<Hex> {
  return (await signer.signMessage(getBytes(userOpHash))) as Hex;
}
