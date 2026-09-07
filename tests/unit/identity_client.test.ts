/**
 * DEVX-S1 / F2 — IdentityClient end-to-end over an injected transport.
 * The fetch double stands in for the HTTP boundary only; the ID token is REAL (RSA-signed)
 * and really verified, and the entitlement→capability mapping is the shipped one.
 */
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

import { FEDERATION_CONTRACT } from '../../src/generated/contract';
import { IdentityClient, type FetchLike } from '../../src/identity/client';
import type { Jwk } from '../../src/identity/jwt';

const ID = FEDERATION_CONTRACT.identity;
const CLIENT_ID = 'citrate-core';
const KID = 'kid-1';

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const JWKS: Jwk[] = [{ ...(publicKey.export({ format: 'jwk' }) as Jwk), kid: KID, use: 'sig', alg: 'RS256' }];
const b64url = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');

function idToken(extra: Record<string, unknown>): string {
  const header = { alg: 'RS256', kid: KID, typ: 'JWT' };
  const payload = {
    iss: ID.issuer,
    sub: 'user-1',
    aud: CLIENT_ID,
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...extra,
  };
  const signingInput = `${b64url(header)}.${b64url(payload)}`;
  return `${signingInput}.${cryptoSign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url')}`;
}

const discovery = {
  issuer: ID.issuer,
  authorization_endpoint: `${ID.issuer}/auth`,
  token_endpoint: `${ID.issuer}/token`,
  userinfo_endpoint: `${ID.issuer}/me`,
  jwks_uri: `${ID.issuer}/jwks`,
  end_session_endpoint: `${ID.issuer}/session/end`,
};

function ok(body: unknown): ReturnType<FetchLike> {
  return Promise.resolve({ ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) });
}

/** Route the fake transport by URL; userinfo body is parameterizable per test. */
function makeFetch(userinfoBody: Record<string, unknown>): FetchLike {
  return (url) => {
    if (url === ID.discovery) return ok(discovery);
    if (url === discovery.jwks_uri) return ok({ keys: JWKS });
    // SJS-B-007: the ID token carries the nonce the exchange asserts ('no').
    if (url === discovery.token_endpoint) return ok({ id_token: idToken({ nonce: 'no' }), access_token: 'at-1', refresh_token: 'rt-1' });
    if (url === discovery.userinfo_endpoint) return ok(userinfoBody);
    if (url === `${ID.issuer}/aa/enroll-validator`) return ok({ digest: '0xd1', signature: '0x51', factory: 'f' });
    return Promise.resolve({ ok: false, status: 404, json: async () => ({}), text: async () => 'not found' });
  };
}

describe('IdentityClient.authorizeUrl', () => {
  it('builds a PKCE S256 authorize URL from the artifact scopes', () => {
    const client = new IdentityClient({ clientId: CLIENT_ID, redirectUri: 'http://127.0.0.1:8899/auth/callback', fetch: makeFetch({}) });
    const { url, pkce } = client.authorizeUrl({ state: 'st', nonce: 'no' });
    expect(url).toContain(`${ID.issuer}/auth?`);
    expect(url).toContain('code_challenge_method=S256');
    expect(url).toContain(`code_challenge=${pkce.challenge}`);
    expect(url).toContain('scope=openid+profile+wallet+kyc+offline_access');
    expect(url).toContain(`client_id=${CLIENT_ID}`);
  });
});

describe('IdentityClient.exchangeCode', () => {
  it('exchanges a code and verifies the returned ID token', async () => {
    const client = new IdentityClient({ clientId: CLIENT_ID, redirectUri: 'http://127.0.0.1:8899/auth/callback', fetch: makeFetch({}) });
    // SJS-B-007: nonce is required — the same value threaded through authorizeUrl.
    const tokens = await client.exchangeCode({ code: 'abc', codeVerifier: 'v'.repeat(43), nonce: 'no' });
    expect(tokens.claims.sub).toBe('user-1');
    expect(tokens.accessToken).toBe('at-1');
    expect(tokens.refreshToken).toBe('rt-1');
  });

  it('SJS-B-007: exchangeCode rejects a missing/empty nonce (no silent skip of the ID-token binding)', async () => {
    const client = new IdentityClient({ clientId: CLIENT_ID, redirectUri: 'x', fetch: makeFetch({}) });
    await expect(
      // @ts-expect-error nonce is required — omitting it must not typecheck
      client.exchangeCode({ code: 'abc', codeVerifier: 'v'.repeat(43) }),
    ).rejects.toThrow(/nonce/);
    await expect(
      client.exchangeCode({ code: 'abc', codeVerifier: 'v'.repeat(43), nonce: '' }),
    ).rejects.toThrow(/nonce/);
  });
});

describe('IdentityClient.userInfo — normalized capabilities', () => {
  it('commercial.kyc → ecosystemTx, NOT confidentialDocs', async () => {
    const body = { sub: 'user-1', wallet_address: '0x1615Af127952c4e4987D7b597bDD7cb8B49aFB89', [ID.entitlementClaim]: { tier: 'commercial.kyc' } };
    const client = new IdentityClient({ clientId: CLIENT_ID, redirectUri: 'x', fetch: makeFetch(body) });
    const info = await client.userInfo('at-1');
    expect(info.tier).toBe('commercial.kyc');
    expect(info.capabilities.ecosystemTx).toBe(true);
    expect(info.capabilities.confidentialDocs).toBe(false);
    expect(info.walletAddress).toBe('0x1615Af127952c4e4987D7b597bDD7cb8B49aFB89');
  });

  it('an unknown tier collapses to public capabilities', async () => {
    const body = { sub: 'user-1', [ID.entitlementClaim]: { tier: 'made-up' } };
    const client = new IdentityClient({ clientId: CLIENT_ID, redirectUri: 'x', fetch: makeFetch(body) });
    const info = await client.userInfo('at-1');
    expect(info.tier).toBe('public');
    expect(info.capabilities.ecosystemTx).toBe(false);
  });

  it('an unallowlisted role does NOT get confidential capabilities (SJS-B-001)', async () => {
    // Was `.toBe(true)`: the inline copy granted the full capability set to any truthy role.
    // userInfo now routes through resolveCapabilities — an unallowlisted role falls back to tier.
    const body = { sub: 'auditor-1', [ID.entitlementClaim]: { tier: 'public', citrateRole: 'auditor' } };
    const client = new IdentityClient({ clientId: CLIENT_ID, redirectUri: 'x', fetch: makeFetch(body) });
    const info = await client.userInfo('at-1');
    expect(info.capabilities.confidentialDocs).toBe(false);
  });

  it('an expired claim collapses to public through the spine (SJS-B-002)', async () => {
    const body = { sub: 'user-1', [ID.entitlementClaim]: { tier: 'confidential', expiresAt: Date.now() - 86_400_000 } };
    const client = new IdentityClient({ clientId: CLIENT_ID, redirectUri: 'x', fetch: makeFetch(body) });
    const info = await client.userInfo('at-1');
    // Was granted full caps: userInfo never read expiresAt while can() honoured it.
    expect(info.capabilities.confidentialDocs).toBe(false);
    expect(info.capabilities.ecosystemTx).toBe(false);
  });
});

describe('IdentityClient.requestDeployPermit', () => {
  it('returns an authority-signed deploy permit', async () => {
    const client = new IdentityClient({ clientId: CLIENT_ID, redirectUri: 'x', fetch: makeFetch({}) });
    const permit = await client.requestDeployPermit(
      { userId: '0x' + '42'.repeat(32), initData: '0xabcd', expiresAt: 1_780_000_000 },
      'at-1',
    );
    expect(permit.digest).toBe('0xd1');
    expect(permit.signature).toBe('0x51');
  });
});
