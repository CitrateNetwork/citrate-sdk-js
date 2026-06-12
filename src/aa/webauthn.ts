/**
 * Passkey (WebAuthn P-256) UserOp signing (EW-S1 WP-7).
 *
 * The on-chain verifier is the vendored Daimo WebAuthn library behind
 * `WebAuthnP256Validator` (`citrate-chain/contracts/src/aa/`):
 *
 *   - `userOp.signature` = abi.encode(bytes authenticatorData,
 *     string clientDataJSON, uint256 challengeLocation,
 *     uint256 responseTypeLocation, uint256 r, uint256 s)
 *   - `challengeLocation` is the byte index in clientDataJSON where the
 *     exact substring `"challenge":"<base64url(userOpHash)>"` begins;
 *     `responseTypeLocation` likewise for `"type":"webauthn.get"`.
 *   - Daimo's P256 wrapper rejects malleable (high-s) signatures, so we
 *     normalize `s` into the lower half of the curve order.
 *
 * `signUserOpWithPasskey` drives the browser's
 * `navigator.credentials.get()`; the pure encoding/parsing helpers are
 * exported separately so they are unit-testable without a browser.
 */

import { AbiCoder } from 'ethers';

import type { Hex } from './types';

const coder = AbiCoder.defaultAbiCoder();

/** secp256r1 (P-256) group order, and its half for low-s normalization. */
export const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
export const P256_N_DIV_2 = P256_N >> 1n;

export class WebAuthnSigningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WebAuthnSigningError';
  }
}

/** Normalize a P-256 `s` into the lower half-order (the verifier rejects high-s). */
export function normalizeP256S(s: bigint): bigint {
  if (s <= 0n || s >= P256_N) {
    throw new WebAuthnSigningError('s out of range for P-256');
  }
  return s > P256_N_DIV_2 ? P256_N - s : s;
}

/** base64url (no padding) of raw bytes — matches Solidity Base64URL.encode. */
export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 =
    typeof btoa === 'function'
      ? btoa(bin)
      : Buffer.from(bytes).toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Parse an ASN.1/DER ECDSA signature (what WebAuthn assertions carry)
 * into (r, s). Layout: 0x30 len 0x02 rlen r 0x02 slen s.
 */
export function parseDerEcdsaSignature(der: Uint8Array): { r: bigint; s: bigint } {
  if (der.length < 8 || der[0] !== 0x30) {
    throw new WebAuthnSigningError('not a DER ECDSA signature');
  }
  const headerLen = der[1] ?? 0;
  // Long-form length — a 70-72 byte sig never needs more than 1 length byte.
  let offset = headerLen & 0x80 ? 2 + (headerLen & 0x7f) : 2;
  const readInt = (): bigint => {
    if (der[offset] !== 0x02) {
      throw new WebAuthnSigningError('expected DER INTEGER');
    }
    const len = der[offset + 1] ?? 0;
    if (len === 0 || offset + 2 + len > der.length) {
      throw new WebAuthnSigningError('truncated DER INTEGER');
    }
    const start = offset + 2;
    const slice = der.slice(start, start + len);
    offset = start + len;
    let v = 0n;
    for (const b of slice) v = (v << 8n) | BigInt(b);
    return v;
  };
  const r = readInt();
  const s = readInt();
  return { r, s };
}

/** The raw assertion pieces the encoder needs (browser- and test-supplied). */
export interface WebAuthnAssertion {
  authenticatorData: Uint8Array;
  /** Exact UTF-8 clientDataJSON string the authenticator produced. */
  clientDataJSON: string;
  r: bigint;
  s: bigint;
}

/**
 * Encode an assertion into the `userOp.signature` blob the
 * `WebAuthnP256Validator` decodes. `challenge` is the exact bytes the
 * authenticator was asked to sign (for UserOps: the 32-byte userOpHash).
 */
export function encodeWebauthnValidatorSignature(
  assertion: WebAuthnAssertion,
  challenge: Uint8Array,
): Hex {
  const challengeProperty = `"challenge":"${base64UrlEncode(challenge)}"`;
  const challengeLocation = assertion.clientDataJSON.indexOf(challengeProperty);
  if (challengeLocation === -1) {
    throw new WebAuthnSigningError(
      'clientDataJSON does not contain the expected challenge property',
    );
  }
  const responseTypeLocation = assertion.clientDataJSON.indexOf(
    '"type":"webauthn.get"',
  );
  if (responseTypeLocation === -1) {
    throw new WebAuthnSigningError(
      'clientDataJSON is not a webauthn.get assertion',
    );
  }

  return coder.encode(
    ['bytes', 'string', 'uint256', 'uint256', 'uint256', 'uint256'],
    [
      assertion.authenticatorData,
      assertion.clientDataJSON,
      BigInt(challengeLocation),
      BigInt(responseTypeLocation),
      assertion.r,
      normalizeP256S(assertion.s),
    ],
  ) as Hex;
}

/** Options for the browser signing path. */
export interface PasskeySignOptions {
  /** Restrict the prompt to a known credential id (raw bytes), if any. */
  credentialId?: Uint8Array;
  /** WebAuthn relying-party id (defaults to the page's domain). */
  rpId?: string;
  timeoutMs?: number;
  userVerification?: UserVerificationRequirement;
}

/**
 * Browser path: ask the platform authenticator to sign `userOpHash`
 * (as the WebAuthn challenge) and encode the result for the validator.
 * Must run in a secure context with WebAuthn available.
 */
export async function signUserOpWithPasskey(
  userOpHash: Hex,
  options: PasskeySignOptions = {},
): Promise<Hex> {
  if (typeof navigator === 'undefined' || !navigator.credentials) {
    throw new WebAuthnSigningError(
      'WebAuthn is not available in this environment',
    );
  }
  const challenge = hexToBytes(userOpHash);

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: challenge.buffer.slice(0) as ArrayBuffer,
    timeout: options.timeoutMs ?? 60_000,
    userVerification: options.userVerification ?? 'preferred',
    ...(options.rpId ? { rpId: options.rpId } : {}),
    ...(options.credentialId
      ? {
          allowCredentials: [
            {
              type: 'public-key' as const,
              id: options.credentialId.buffer.slice(0) as ArrayBuffer,
            },
          ],
        }
      : {}),
  };

  const cred = (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential | null;
  if (!cred) {
    throw new WebAuthnSigningError('no credential returned');
  }
  const resp = cred.response as AuthenticatorAssertionResponse;
  const { r, s } = parseDerEcdsaSignature(new Uint8Array(resp.signature));

  return encodeWebauthnValidatorSignature(
    {
      authenticatorData: new Uint8Array(resp.authenticatorData),
      clientDataJSON: new TextDecoder().decode(resp.clientDataJSON),
      r,
      s,
    },
    challenge,
  );
}

function hexToBytes(hex: Hex): Uint8Array {
  const clean = hex.slice(2);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
