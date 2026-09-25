/**
 * PBA-L3a-011 (SDK part, LOW) and PBA-L3a-012 (INFO), 2026-09-24 pre-bounty audit.
 *
 * L3a-011: `verifyIdToken` accepted an ID token with no `exp` (it only checked
 * expiry when `exp` happened to be a number), and `IdentityClient.refresh()`
 * did not check that the refreshed ID token names the same `sub`.
 *
 * L3a-012: the SIWE client did not match the server. `siweChallenge` POSTed to
 * a GET-only route, and `siweVerify` expected `access_token`/`refresh_token`
 * that `/siwe/verify` never returns.
 *
 * The SIWE part is a CONTRACT test. `identityServer()` below is a transcription
 * of citrate-identity `src/siwe-routes.ts` at 08959bf (the route table, the
 * request shapes it accepts, the two success shapes and the error shapes) and
 * of the `verifySiweLogin` message rules in `src/siwe.ts` (chain 40204,
 * mandatory Expiration Time <= 24 h, `uri` host == authority domain). If the
 * server changes any of those, update this fixture and the client together.
 */
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { getAddress } from 'ethers';

import { FEDERATION_CONTRACT } from '../../src/generated/contract';
import { IdentityClient, buildSiweMessage, type FetchLike } from '../../src/identity/client';
import { IdTokenError, verifyIdToken, type Jwk } from '../../src/identity/jwt';

const ID = FEDERATION_CONTRACT.identity;
const CLIENT_ID = 'citrate-core';
const KID = 'kid-r2';
const ADDRESS = getAddress('0x' + 'ab'.repeat(20));

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const JWKS: Jwk[] = [{ ...(publicKey.export({ format: 'jwk' }) as Jwk), kid: KID, use: 'sig', alg: 'RS256' }];
const b64url = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');

function idToken(payload: Record<string, unknown>): string {
  const input = `${b64url({ alg: 'RS256', kid: KID, typ: 'JWT' })}.${b64url(payload)}`;
  return `${input}.${cryptoSign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
}
const nowSec = () => Math.floor(Date.now() / 1000);
const base = (extra: Record<string, unknown> = {}) => ({
  iss: ID.issuer,
  sub: 'user-1',
  aud: CLIENT_ID,
  iat: nowSec(),
  exp: nowSec() + 3600,
  ...extra,
});

describe('PBA-L3a-011: verifyIdToken requires a numeric exp', () => {
  const opts = { issuer: ID.issuer, audience: CLIENT_ID, jwks: JWKS };

  it('rejects a token with no exp', () => {
    const { exp: _drop, ...noExp } = base();
    expect(() => verifyIdToken(idToken(noExp), opts)).toThrow(IdTokenError);
    expect(() => verifyIdToken(idToken(noExp), opts)).toThrow(/exp/);
  });

  it.each(['9999999999', null, true, NaN, Infinity])('rejects a non-numeric or non-finite exp (%p)', (exp) => {
    expect(() => verifyIdToken(idToken(base({ exp })), opts)).toThrow(/exp/);
  });

  it('still accepts a valid token and still rejects an expired one', () => {
    expect(verifyIdToken(idToken(base()), opts).sub).toBe('user-1');
    expect(() => verifyIdToken(idToken(base({ exp: nowSec() - 3600 })), opts)).toThrow(/expired/);
  });

  it('honours the clock tolerance at the boundary', () => {
    const now = Date.now();
    const exp = Math.floor(now / 1000) - 60; // exactly at the 60 s tolerance edge
    expect(verifyIdToken(idToken(base({ exp })), { ...opts, now }).sub).toBe('user-1');
    expect(() => verifyIdToken(idToken(base({ exp: exp - 1 })), { ...opts, now })).toThrow(/expired/);
  });
});

// ── a transcription of the citrate-identity routes the SDK talks to ──────────
interface Call { url: string; method: string; body?: string; headers?: Record<string, string> }
function identityServer(opts: { refreshedSub?: string; directTokenGrant?: boolean; interaction?: boolean } = {}) {
  const calls: Call[] = [];
  const issued = new Set<string>();
  const discovery = {
    issuer: ID.issuer,
    authorization_endpoint: `${ID.issuer}/auth`,
    token_endpoint: `${ID.issuer}/token`,
    userinfo_endpoint: `${ID.issuer}/me`,
    jwks_uri: `${ID.issuer}/jwks`,
  };
  const res = (status: number, body: unknown) =>
    Promise.resolve({ ok: status >= 200 && status < 300, status, json: async () => body, text: async () => JSON.stringify(body) });
  const fetch: FetchLike = (url, init) => {
    const method = init?.method ?? 'GET';
    calls.push({ url, method, headers: init?.headers ?? {}, ...(init?.body !== undefined ? { body: init.body } : {}) });
    if (url === ID.discovery && method === 'GET') return res(200, discovery);
    if (url === discovery.jwks_uri && method === 'GET') return res(200, { keys: JWKS });
    if (url === discovery.token_endpoint && method === 'POST') {
      return res(200, {
        id_token: idToken(base({ sub: opts.refreshedSub ?? 'user-1' })),
        access_token: 'at-2',
        refresh_token: 'rt-2',
      });
    }
    // siwe-routes.ts: `if (method === 'GET' && path === '/siwe/challenge')`.
    // Any other method falls through to panva, which has no such route (404).
    if (url === `${ID.issuer}/siwe/challenge`) {
      if (method !== 'GET') return res(404, { error: 'invalid_request' });
      const nonce = `n${issued.size + 1}abcdefgh`;
      issued.add(nonce);
      return res(200, { nonce });
    }
    if (url === `${ID.issuer}/siwe/verify`) {
      if (method !== 'POST') return res(404, { error: 'invalid_request' });
      let body: { message?: unknown; signature?: unknown };
      try {
        body = JSON.parse(init?.body ?? '');
      } catch {
        return res(400, { error: 'invalid_request', reason: 'bad_body' });
      }
      if (typeof body.message !== 'string' || typeof body.signature !== 'string') {
        return res(400, { error: 'invalid_request', reason: 'message and signature are required strings' });
      }
      const m = body.message;
      const nonce = /\nNonce: (\S+)/.exec(m)?.[1];
      if (!nonce || !issued.delete(nonce)) return res(401, { error: 'invalid_grant', reason: 'unknown_nonce' });
      if (!/\nChain ID: 40204\n/.test(m)) return res(401, { error: 'invalid_grant', reason: 'wrong_chain' });
      const exp = /\nExpiration Time: (\S+)/.exec(m)?.[1];
      if (!exp || Number.isNaN(Date.parse(exp))) return res(401, { error: 'invalid_grant', reason: 'missing_expiration' });
      if (Date.parse(exp) - Date.now() > 24 * 3600 * 1000) return res(401, { error: 'invalid_grant', reason: 'expiration_too_far' });
      const domain = new URL(ID.issuer).host;
      const uri = /\nURI: (\S+)/.exec(m)?.[1];
      if (!uri || new URL(uri).host !== domain) return res(401, { error: 'invalid_grant', reason: 'uri_mismatch' });
      if (!m.startsWith(`${domain} wants you to sign in with your Ethereum account:\n${ADDRESS}\n`)) {
        return res(401, { error: 'invalid_grant', reason: 'domain_mismatch' });
      }
      if (opts.interaction) return res(200, { address: ADDRESS, method: 'eoa', redirectTo: `${ID.issuer}/auth/xyz` });
      if (!opts.directTokenGrant) {
        return res(400, {
          error: 'invalid_request',
          reason: 'no active OIDC interaction; the direct token grant is disabled — use the authorization code flow',
        });
      }
      return res(200, {
        address: ADDRESS,
        method: 'eoa',
        token_type: 'Bearer',
        id_token: idToken(base({ sub: ADDRESS.toLowerCase(), wallet_address: ADDRESS })),
        wallet_address: ADDRESS,
      });
    }
    return res(404, {});
  };
  return { fetch, calls };
}

const client = (fetch: FetchLike) =>
  new IdentityClient({ clientId: CLIENT_ID, redirectUri: 'http://127.0.0.1:8899/cb', fetch });

describe('PBA-L3a-011: refresh() asserts the subject is unchanged', () => {
  it('accepts a refreshed token for the same sub', async () => {
    const { fetch } = identityServer();
    const t = await client(fetch).refresh('rt-1', 'user-1');
    expect(t.claims.sub).toBe('user-1');
    expect(t.refreshToken).toBe('rt-2');
  });

  it('rejects a refreshed token that names a different sub', async () => {
    const { fetch } = identityServer({ refreshedSub: 'user-2' });
    await expect(client(fetch).refresh('rt-1', 'user-1')).rejects.toThrow(/sub changed/);
  });

  it('requires the expected sub', async () => {
    const { fetch } = identityServer();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await expect((client(fetch) as any).refresh('rt-1')).rejects.toThrow(/expectedSub/);
    await expect(client(fetch).refresh('rt-1', '')).rejects.toThrow(/expectedSub/);
  });
});

describe('PBA-L3a-012: SIWE client matches the citrate-identity routes (contract)', () => {
  it('siweChallenge uses GET /siwe/challenge and returns the nonce', async () => {
    const { fetch, calls } = identityServer();
    const { nonce } = await client(fetch).siweChallenge();
    expect(nonce).toMatch(/^n1/);
    const call = calls.find((c) => c.url.endsWith('/siwe/challenge'))!;
    expect(call.method).toBe('GET');
    expect(call.body).toBeUndefined();
  });

  it('buildSiweMessage produces a message the server accepts (chain, expiry, uri, domain)', async () => {
    const { fetch } = identityServer({ directTokenGrant: true });
    const c = client(fetch);
    const { nonce } = await c.siweChallenge();
    const message = buildSiweMessage({ address: ADDRESS, nonce });
    expect(message).toContain('\nVersion: 1\n');
    expect(message).toContain('\nChain ID: 40204\n');
    expect(message).toMatch(/\nExpiration Time: \S+/);
    const r = await c.siweVerify({ message, signature: '0x' + '11'.repeat(65) });
    expect(r.kind).toBe('token');
  });

  it('buildSiweMessage refuses an expiry beyond the server cap', () => {
    expect(() => buildSiweMessage({ address: ADDRESS, nonce: 'abcdefgh', ttlSeconds: 25 * 3600 })).toThrow(/24 h/);
  });

  it('direct-token path: verifies the ID token and needs no access/refresh token', async () => {
    const { fetch } = identityServer({ directTokenGrant: true });
    const c = client(fetch);
    const { nonce } = await c.siweChallenge();
    const r = await c.siweVerify({ message: buildSiweMessage({ address: ADDRESS, nonce }), signature: '0x' + '11'.repeat(65) });
    if (r.kind !== 'token') throw new Error('expected token');
    expect(r.address).toBe(ADDRESS);
    expect(r.idToken.split('.')).toHaveLength(3);
    expect(r.claims.sub).toBe(ADDRESS.toLowerCase());
  });

  it('interaction path: returns the redirect the browser must follow', async () => {
    const { fetch } = identityServer({ interaction: true });
    const c = client(fetch);
    const { nonce } = await c.siweChallenge();
    const r = await c.siweVerify({ message: buildSiweMessage({ address: ADDRESS, nonce }), signature: '0x' + '11'.repeat(65) });
    expect(r).toEqual({ kind: 'redirect', address: ADDRESS, method: 'eoa', redirectTo: `${ID.issuer}/auth/xyz` });
  });

  it('surfaces the server rejection reason (direct grant disabled)', async () => {
    const { fetch } = identityServer();
    const c = client(fetch);
    const { nonce } = await c.siweChallenge();
    await expect(
      c.siweVerify({ message: buildSiweMessage({ address: ADDRESS, nonce }), signature: '0x' + '11'.repeat(65) }),
    ).rejects.toThrow(/direct token grant is disabled/);
  });

  it('a forged ID token from /siwe/verify is rejected', async () => {
    const { fetch: inner } = identityServer({ directTokenGrant: true });
    const fetch: FetchLike = async (url, init) => {
      const r = await inner(url, init);
      if (!url.endsWith('/siwe/verify')) return r;
      const body = (await r.json()) as Record<string, string>;
      const [h, p] = body['id_token']!.split('.');
      return { ...r, json: async () => ({ ...body, id_token: `${h}.${p}.AAAA` }) };
    };
    const c = client(fetch);
    const { nonce } = await c.siweChallenge();
    await expect(
      c.siweVerify({ message: buildSiweMessage({ address: ADDRESS, nonce }), signature: '0x' + '11'.repeat(65) }),
    ).rejects.toThrow(/signature verification failed/);
  });
});

// ── mutation-hardening (Stryker survivors from the first run) ───────────────
function rawToken(payloadJson: string): string {
  const input = `${b64url({ alg: 'RS256', kid: KID, typ: 'JWT' })}.${Buffer.from(payloadJson).toString('base64url')}`;
  return `${input}.${cryptoSign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
}

describe('verifyIdToken edges', () => {
  const opts = { issuer: ID.issuer, audience: CLIENT_ID, jwks: JWKS };
  it('rejects exp that parses to Infinity (1e400)', () => {
    const json = `{"iss":"${ID.issuer}","sub":"u","aud":"${CLIENT_ID}","exp":1e400}`;
    expect(() => verifyIdToken(rawToken(json), opts)).toThrow(/no numeric exp/);
  });
  it('nbf: future beyond tolerance rejected, within tolerance accepted', () => {
    const now = Date.now();
    const s = Math.floor(now / 1000);
    expect(() => verifyIdToken(idToken(base({ nbf: s + 61 })), { ...opts, now })).toThrow(/not yet valid/);
    expect(verifyIdToken(idToken(base({ nbf: s + 60 })), { ...opts, now }).sub).toBe('user-1');
    expect(verifyIdToken(idToken(base({ nbf: 'x' })), { ...opts, now }).sub).toBe('user-1');
  });
  it('nonce: enforced only when supplied', () => {
    expect(() => verifyIdToken(idToken(base({ nonce: 'a' })), { ...opts, nonce: 'b' })).toThrow(/nonce mismatch/);
    expect(verifyIdToken(idToken(base({ nonce: 'a' })), { ...opts, nonce: 'a' }).sub).toBe('user-1');
    expect(verifyIdToken(idToken(base({ nonce: 'a' })), opts).sub).toBe('user-1');
  });
});

describe('buildSiweMessage exact output and input checks', () => {
  const issuedAt = new Date('2026-09-25T00:00:00.000Z');
  const domain = new URL(ID.issuer).host;
  it('matches EIP-4361 byte for byte (no statement)', () => {
    expect(buildSiweMessage({ address: ADDRESS, nonce: 'abcdefgh', issuedAt })).toBe(
      `${domain} wants you to sign in with your Ethereum account:\n${ADDRESS}\n\n\n` +
        `URI: ${new URL(ID.issuer).origin}\nVersion: 1\nChain ID: 40204\nNonce: abcdefgh\n` +
        'Issued At: 2026-09-25T00:00:00.000Z\nExpiration Time: 2026-09-25T00:10:00.000Z',
    );
  });
  it('matches EIP-4361 byte for byte (statement, custom ttl)', () => {
    expect(buildSiweMessage({ address: ADDRESS.toLowerCase(), nonce: 'abcdefgh', issuedAt, statement: 'Hi', ttlSeconds: 86400 })).toBe(
      `${domain} wants you to sign in with your Ethereum account:\n${ADDRESS}\n\nHi\n\n` +
        `URI: ${new URL(ID.issuer).origin}\nVersion: 1\nChain ID: 40204\nNonce: abcdefgh\n` +
        'Issued At: 2026-09-25T00:00:00.000Z\nExpiration Time: 2026-09-26T00:00:00.000Z',
    );
  });
  it.each([
    [{ uri: 'https://evil.example/login' }, /authority domain/],
    [{ address: '0x1234' }, /valid 20-byte hex address/],
    [{ nonce: 'abc' }, /nonce must be/],
    [{ nonce: '-abcdefgh' }, /nonce must be/],
    [{ nonce: 'abcdefgh-' }, /nonce must be/],
    [{ ttlSeconds: 0 }, /ttlSeconds/],
    [{ ttlSeconds: -5 }, /ttlSeconds/],
    [{ ttlSeconds: 1.5 }, /ttlSeconds/],
    [{ ttlSeconds: 86401 }, /24 h/],
  ])('rejects %p', (extra, re) => {
    expect(() => buildSiweMessage({ address: ADDRESS, nonce: 'abcdefgh', ...extra })).toThrow(re as RegExp);
  });
  it('accepts a same-host uri with a path', () => {
    expect(buildSiweMessage({ address: ADDRESS, nonce: 'abcdefgh', uri: `${ID.issuer}/login` })).toContain(`URI: ${ID.issuer}/login`);
  });
});

describe('IdentityClient transport details', () => {
  const resp = (status: number, body: unknown) =>
    Promise.resolve({ ok: status < 300, status, json: async () => body, text: async () => '' });
  it('refresh posts a refresh_token grant and names both subs on mismatch', async () => {
    const { fetch, calls } = identityServer({ refreshedSub: 'user-2' });
    await expect(client(fetch).refresh('rt-1', 'user-1')).rejects.toThrow(/sub changed \(user-2 != user-1\)/);
    const tok = calls.find((c) => c.url.endsWith('/token'))!;
    expect(new URLSearchParams(tok.body).get('grant_type')).toBe('refresh_token');
    expect(new URLSearchParams(tok.body).get('refresh_token')).toBe('rt-1');
    expect(new URLSearchParams(tok.body).get('client_id')).toBe(CLIENT_ID);
  });
  it('exchangeCode enforces the nonce and omits an absent refresh token', async () => {
    const { fetch: inner } = identityServer();
    const fetch: FetchLike = async (url, init) =>
      url.endsWith('/token') ? resp(200, { id_token: idToken(base({ nonce: 'n-1' })), access_token: 'at' }) : inner(url, init);
    const c = client(fetch);
    await expect(c.exchangeCode({ code: 'c', codeVerifier: 'v'.repeat(43), nonce: 'other' })).rejects.toThrow(/nonce mismatch/);
    const t = await c.exchangeCode({ code: 'c', codeVerifier: 'v'.repeat(43), nonce: 'n-1' });
    expect('refreshToken' in t).toBe(false);
  });
  it('siweChallenge rejects a missing or short nonce; accepts exactly 8 chars', async () => {
    for (const [body, ok] of [[{}, false], [{ nonce: 'abcdefg' }, false], [{ nonce: 12345678 }, false], [{ nonce: 'abcdefgh' }, true]] as const) {
      const fetch: FetchLike = () => resp(200, body);
      const p = client(fetch).siweChallenge();
      if (ok) await expect(p).resolves.toEqual({ nonce: 'abcdefgh' });
      else await expect(p).rejects.toThrow(/no nonce/);
    }
  });
  it('siweVerify sends JSON with only message and signature', async () => {
    const { fetch, calls } = identityServer({ directTokenGrant: true });
    const c = client(fetch);
    const { nonce } = await c.siweChallenge();
    const message = buildSiweMessage({ address: ADDRESS, nonce });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await c.siweVerify({ message, signature: '0xab', extra: 'x' } as any);
    const v = calls.find((x) => x.url.endsWith('/siwe/verify'))!;
    expect(v.method).toBe('POST');
    expect(v.headers).toEqual({ 'content-type': 'application/json' });
    expect(JSON.parse(v.body!)).toEqual({ message, signature: '0xab' });
  });
  it('siweVerify error text: reason, else error, else bare status', async () => {
    const mk = (status: number, body: unknown) => client(() => resp(status, body));
    await expect(mk(401, { error: 'invalid_grant', reason: 'unknown_nonce' }).siweVerify({ message: 'm', signature: 's' })).rejects.toThrow(
      /failed: 401 \(unknown_nonce\)$/,
    );
    await expect(mk(401, { error: 'invalid_grant' }).siweVerify({ message: 'm', signature: 's' })).rejects.toThrow(/failed: 401 \(invalid_grant\)$/);
    await expect(mk(500, {}).siweVerify({ message: 'm', signature: 's' })).rejects.toThrow(/failed: 500$/);
    const bad = client(() => Promise.resolve({ ok: false, status: 502, json: async () => { throw new Error('html'); }, text: async () => '' }));
    await expect(bad.siweVerify({ message: 'm', signature: 's' })).rejects.toThrow(/failed: 502$/);
  });
  it('siweVerify success-shape edges', async () => {
    await expect(client(() => resp(200, { redirectTo: 'https://x' })).siweVerify({ message: 'm', signature: 's' })).resolves.toEqual({
      kind: 'redirect', address: '', method: '', redirectTo: 'https://x',
    });
    await expect(client(() => resp(200, { address: 1, method: 2, redirectTo: 'https://x' })).siweVerify({ message: 'm', signature: 's' })).resolves.toEqual({
      kind: 'redirect', address: '', method: '', redirectTo: 'https://x',
    });
    await expect(client(() => resp(200, { address: ADDRESS })).siweVerify({ message: 'm', signature: 's' })).rejects.toThrow(
      /neither redirectTo nor id_token/,
    );
    await expect(client(() => resp(200, { id_token: 5 })).siweVerify({ message: 'm', signature: 's' })).rejects.toThrow(
      /neither redirectTo nor id_token/,
    );
  });
});
