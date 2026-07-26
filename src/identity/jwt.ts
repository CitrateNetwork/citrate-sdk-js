/**
 * ID-token verification (DEVX-S1). Zero deps (node:crypto).
 *
 * Hardened against the classic OIDC attacks that hit the citrate-core A3 work:
 *  - alg:none            → rejected (RS256 is the only accepted alg)
 *  - alg-confusion (HS*) → rejected (we never treat the RSA public key as an HMAC secret)
 *  - wrong aud / iss     → rejected
 *  - expired / not-before→ rejected (with a small clock tolerance)
 *  - tampered signature  → rejected (RSA-SHA256 verify over the exact signing input)
 *
 * The authority signs RS256 (jwks kid e.g. citrate-1780633938850). We fetch the JWKS,
 * pick the key by `kid`, and verify. No token claim is trusted before the signature.
 */
import { createPublicKey, verify as cryptoVerify, type JsonWebKey } from 'node:crypto';

export class IdTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdTokenError';
  }
}

export interface Jwk {
  kty: string;
  kid?: string;
  n?: string;
  e?: string;
  alg?: string;
  use?: string;
}

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp?: number;
  iat?: number;
  nbf?: number;
  nonce?: string;
  [k: string]: unknown;
}

export interface VerifyIdTokenOptions {
  issuer: string;
  audience: string;
  jwks: Jwk[];
  /** epoch-ms; defaults to Date.now(). */
  now?: number;
  /** seconds of allowed clock skew (default 60). */
  clockToleranceSec?: number;
  /** if set, require this nonce (returned from the auth request). */
  nonce?: string;
}

function decodeSegment(seg: string): Record<string, unknown> {
  try {
    return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
  } catch {
    throw new IdTokenError('malformed token segment');
  }
}

/** Verify an OIDC ID token and return its (now-trusted) claims. Throws IdTokenError on any failure. */
export function verifyIdToken(token: string, opts: VerifyIdTokenOptions): IdTokenClaims {
  const parts = token.split('.');
  if (parts.length !== 3) throw new IdTokenError('token must have three segments');
  const [headerSeg, payloadSeg, sigSeg] = parts as [string, string, string];

  const header = decodeSegment(headerSeg);
  // ALG allowlist — the single most important check. RS256 only.
  if (header['alg'] !== 'RS256') {
    throw new IdTokenError(`unsupported or unsafe alg: ${String(header['alg'])} (only RS256 accepted)`);
  }
  if (sigSeg.length === 0) throw new IdTokenError('empty signature');

  const kid = typeof header['kid'] === 'string' ? (header['kid'] as string) : undefined;
  const rsaKeys = opts.jwks.filter((k) => k.kty === 'RSA' && k.n && k.e);
  const jwk = kid ? rsaKeys.find((k) => k.kid === kid) : rsaKeys.length === 1 ? rsaKeys[0] : undefined;
  if (!jwk) throw new IdTokenError(kid ? `no RSA JWK for kid ${kid}` : 'ambiguous or missing RSA JWK');

  const pub = createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e } as JsonWebKey, format: 'jwk' });
  const ok = cryptoVerify(
    'RSA-SHA256',
    Buffer.from(`${headerSeg}.${payloadSeg}`),
    pub,
    Buffer.from(sigSeg, 'base64url'),
  );
  if (!ok) throw new IdTokenError('signature verification failed');

  const payload = decodeSegment(payloadSeg) as IdTokenClaims;

  if (payload.iss !== opts.issuer) throw new IdTokenError(`iss mismatch: ${payload.iss}`);
  const aud = payload.aud;
  const audOk = Array.isArray(aud) ? aud.includes(opts.audience) : aud === opts.audience;
  if (!audOk) throw new IdTokenError('aud mismatch');

  const nowSec = Math.floor((opts.now ?? Date.now()) / 1000);
  const tol = opts.clockToleranceSec ?? 60;
  if (typeof payload.exp === 'number' && nowSec > payload.exp + tol) throw new IdTokenError('token expired');
  if (typeof payload.nbf === 'number' && nowSec + tol < payload.nbf) throw new IdTokenError('token not yet valid');
  if (opts.nonce !== undefined && payload.nonce !== opts.nonce) throw new IdTokenError('nonce mismatch');

  return payload;
}
