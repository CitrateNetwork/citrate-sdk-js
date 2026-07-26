/**
 * PKCE (RFC 7636) for the Citrate OIDC flow (DEVX-S1). Zero deps (node:crypto).
 * The authority mandates S256 for all clients.
 */
import { createHash, randomBytes } from 'node:crypto';

export interface Pkce {
  /** The high-entropy secret kept by the client and sent to /token. */
  verifier: string;
  /** base64url(sha256(verifier)) — sent to /auth. */
  challenge: string;
  method: 'S256';
}

/** A 43-char base64url verifier (256 bits of entropy). */
export function generateVerifier(): string {
  return randomBytes(32).toString('base64url');
}

/** S256 challenge for a verifier. */
export function challengeFromVerifier(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

export function createPkce(): Pkce {
  const verifier = generateVerifier();
  return { verifier, challenge: challengeFromVerifier(verifier), method: 'S256' };
}
