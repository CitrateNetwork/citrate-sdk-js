/**
 * Variant of PBA-L6b-029 (Python) in the JS SDK: verifyIdToken did not check
 * `typ` (an `at+jwt` access token or `logout+jwt` token signed by the same key
 * for the same audience passed as an ID token) and did not require `iat`.
 * Both SDKs now apply the same rule: typ absent or JWT, numeric exp and iat.
 */
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { verifyIdToken, type Jwk } from '../../src/identity/jwt';

const ISS = 'https://auth.citrate.ai';
const AUD = 'citrate-core';
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const JWKS: Jwk[] = [{ ...(publicKey.export({ format: 'jwk' }) as Jwk), kid: 'k' }];
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const tok = (payload: Record<string, unknown>, header: Record<string, unknown>) => {
  const input = `${b64(header)}.${b64(payload)}`;
  return `${input}.${cryptoSign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
};
const now = () => Math.floor(Date.now() / 1000);
const claims = (x: Record<string, unknown> = {}) => ({ iss: ISS, aud: AUD, sub: 'u', iat: now(), exp: now() + 600, ...x });
const opts = { issuer: ISS, audience: AUD, jwks: JWKS };

describe('PBA-L6b-029 variant: ID-token typ and iat', () => {
  it.each(['at+jwt', 'logout+jwt', 'JWS', '', 5])('rejects typ %p', (typ) => {
    expect(() => verifyIdToken(tok(claims(), { alg: 'RS256', kid: 'k', typ }), opts)).toThrow(/typ/);
  });
  it.each([{ alg: 'RS256', kid: 'k' }, { alg: 'RS256', kid: 'k', typ: 'JWT' }, { alg: 'RS256', kid: 'k', typ: 'jwt' }])(
    'accepts header %p',
    (h) => {
      expect(verifyIdToken(tok(claims(), h), opts).sub).toBe('u');
    },
  );
  it('requires a numeric iat', () => {
    const { iat: _i, ...noIat } = claims();
    expect(() => verifyIdToken(tok(noIat, { alg: 'RS256', kid: 'k' }), opts)).toThrow(/iat/);
    expect(() => verifyIdToken(tok(claims({ iat: '1' }), { alg: 'RS256', kid: 'k' }), opts)).toThrow(/iat/);
  });
});
