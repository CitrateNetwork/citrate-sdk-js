/**
 * DEVX-S1 / F2 — PKCE + hardened ID-token verification. Zero deps (node:crypto).
 * Uses a locally-generated RSA keypair (no mocks of chain/identity data — this is real crypto).
 */
import { createHmac, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

import { challengeFromVerifier, createPkce, generateVerifier } from '../../src/identity/pkce';
import { IdTokenError, verifyIdToken, type Jwk } from '../../src/identity/jwt';

const ISSUER = 'https://auth.citrate.ai';
const AUD = 'citrate-core';
const KID = 'test-kid-1';

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwkPub = publicKey.export({ format: 'jwk' }) as Jwk;
const JWKS: Jwk[] = [{ ...jwkPub, kid: KID, use: 'sig', alg: 'RS256' }];

const b64url = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString('base64url');

function makeToken(
  payload: Record<string, unknown>,
  header: Record<string, unknown> = { alg: 'RS256', kid: KID, typ: 'JWT' },
): string {
  const signingInput = `${b64url(header)}.${b64url(payload)}`;
  const sig = cryptoSign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url');
  return `${signingInput}.${sig}`;
}

const validPayload = () => ({
  iss: ISSUER,
  sub: 'user-1',
  aud: AUD,
  exp: Math.floor(Date.now() / 1000) + 3600,
  iat: Math.floor(Date.now() / 1000),
});

describe('PKCE (S256)', () => {
  it('verifier is 43-char base64url and challenge is its sha256', () => {
    const p = createPkce();
    expect(p.method).toBe('S256');
    expect(p.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.challenge).toBe(challengeFromVerifier(p.verifier));
  });

  it('verifiers are unique', () => {
    expect(generateVerifier()).not.toBe(generateVerifier());
  });
});

describe('verifyIdToken — happy path', () => {
  it('accepts a correctly-signed token and returns claims', () => {
    const claims = verifyIdToken(makeToken(validPayload()), { issuer: ISSUER, audience: AUD, jwks: JWKS });
    expect(claims.sub).toBe('user-1');
  });

  it('accepts an array aud that includes the audience', () => {
    const claims = verifyIdToken(makeToken({ ...validPayload(), aud: ['other', AUD] }), {
      issuer: ISSUER,
      audience: AUD,
      jwks: JWKS,
    });
    expect(claims.sub).toBe('user-1');
  });
});

describe('verifyIdToken — attack rejections', () => {
  it('rejects alg:none', () => {
    const header = { alg: 'none', typ: 'JWT' };
    const token = `${b64url(header)}.${b64url(validPayload())}.`;
    expect(() => verifyIdToken(token, { issuer: ISSUER, audience: AUD, jwks: JWKS })).toThrow(IdTokenError);
  });

  it('rejects alg-confusion (HS256 signed with the RSA public key as secret)', () => {
    const header = { alg: 'HS256', kid: KID, typ: 'JWT' };
    const signingInput = `${b64url(header)}.${b64url(validPayload())}`;
    const forged = createHmac('sha256', JSON.stringify(jwkPub)).update(signingInput).digest('base64url');
    expect(() =>
      verifyIdToken(`${signingInput}.${forged}`, { issuer: ISSUER, audience: AUD, jwks: JWKS }),
    ).toThrow(/RS256/);
  });

  it('rejects a wrong audience', () => {
    expect(() => verifyIdToken(makeToken(validPayload()), { issuer: ISSUER, audience: 'someone-else', jwks: JWKS })).toThrow(/aud/);
  });

  it('rejects a wrong issuer', () => {
    expect(() =>
      verifyIdToken(makeToken({ ...validPayload(), iss: 'https://evil.example' }), { issuer: ISSUER, audience: AUD, jwks: JWKS }),
    ).toThrow(/iss/);
  });

  it('rejects an expired token (beyond tolerance)', () => {
    const past = { ...validPayload(), exp: Math.floor(Date.now() / 1000) - 3600 };
    expect(() => verifyIdToken(makeToken(past), { issuer: ISSUER, audience: AUD, jwks: JWKS })).toThrow(/expired/);
  });

  it('rejects a tampered payload (signature no longer matches)', () => {
    const token = makeToken(validPayload());
    const [h, , s] = token.split('.');
    const tampered = `${h}.${b64url({ ...validPayload(), sub: 'attacker' })}.${s}`;
    expect(() => verifyIdToken(tampered, { issuer: ISSUER, audience: AUD, jwks: JWKS })).toThrow(/signature/);
  });

  it('rejects when no JWK matches the kid', () => {
    const otherJwks: Jwk[] = [{ ...jwkPub, kid: 'different-kid' }];
    expect(() => verifyIdToken(makeToken(validPayload()), { issuer: ISSUER, audience: AUD, jwks: otherJwks })).toThrow(/kid/);
  });
});
