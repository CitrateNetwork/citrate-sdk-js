/**
 * IdentityClient (DEVX-S1) — the turnkey Citrate authorization spine.
 *
 * Wraps the citrate-identity authority (auth.citrate.ai): OIDC PKCE + SIWE sign-in, ID-token
 * verification, userinfo (with normalized entitlement capabilities), and logout. Endpoints,
 * scopes, and the entitlement claim URI come from the federation contract artifact (DEVX-S0).
 *
 * Fail-closed and stateless: it holds no keys, verifies every ID token before trusting a
 * claim, and returns typed errors rather than guesses. `fetch` is injectable for testing.
 */
import { FEDERATION_CONTRACT } from '../generated/contract';
import { resolveCapabilities, normalizeTier, type CapabilitySet, type Tier } from '../entitlements/capabilities';
import { createPkce, type Pkce } from './pkce';
import { verifyIdToken, type IdTokenClaims, type Jwk } from './jwt';

export class IdentityError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = 'IdentityError';
  }
}

export type FetchLike = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}>;

export interface IdentityClientConfig {
  clientId: string;
  redirectUri: string;
  /** Defaults to the artifact scope set. */
  scopes?: string[];
  /** Injectable HTTP transport (defaults to global fetch). */
  fetch?: FetchLike;
}

interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  issuer: string;
}

export interface TokenSet {
  idToken: string;
  accessToken: string;
  refreshToken?: string;
  claims: IdTokenClaims;
}

export interface UserInfo {
  sub: string;
  walletAddress?: string;
  wallets?: string[];
  kycStatus?: string;
  /** Normalized entitlement tier (unknown collapses to public). */
  tier: Tier;
  /** Capability set derived from the tier + role (ADR-0002). */
  capabilities: CapabilitySet;
  raw: Record<string, unknown>;
}

/** A factory deploy permit signed by the authority's identity-signer. */
export interface DeployPermit {
  digest: string;
  signature: string;
  [k: string]: unknown;
}

const ID = FEDERATION_CONTRACT.identity;

export class IdentityClient {
  private readonly fetch: FetchLike;
  private readonly scopes: string[];
  private discovery?: Discovery;
  private jwksCache?: Jwk[];

  constructor(private readonly config: IdentityClientConfig) {
    const f = config.fetch ?? (globalThis.fetch as unknown as FetchLike | undefined);
    if (!f) throw new IdentityError('no fetch implementation available; pass config.fetch');
    this.fetch = f;
    this.scopes = config.scopes ?? ID.scopes;
  }

  /** Fetch + cache the OIDC discovery document (issuer pinned to the artifact). */
  async discover(): Promise<Discovery> {
    if (this.discovery) return this.discovery;
    const doc = (await this.getJson(ID.discovery)) as Discovery;
    if (doc.issuer !== ID.issuer) throw new IdentityError(`issuer mismatch: ${doc.issuer} != ${ID.issuer}`);
    this.discovery = doc;
    return doc;
  }

  private async getJwks(): Promise<Jwk[]> {
    if (this.jwksCache) return this.jwksCache;
    const disc = await this.discover().catch(() => undefined);
    const uri = disc?.jwks_uri ?? ID.jwks;
    const body = (await this.getJson(uri)) as { keys?: Jwk[] };
    if (!body.keys || body.keys.length === 0) throw new IdentityError('JWKS has no keys');
    this.jwksCache = body.keys;
    return body.keys;
  }

  /** Build the /auth URL. Pure once PKCE is created; the verifier stays with the caller. */
  authorizeUrl(opts: { state: string; nonce: string; pkce?: Pkce; scopes?: string[] }): { url: string; pkce: Pkce } {
    const pkce = opts.pkce ?? createPkce();
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: (opts.scopes ?? this.scopes).join(' '),
      state: opts.state,
      nonce: opts.nonce,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    });
    const base = this.discovery?.authorization_endpoint ?? `${ID.issuer}/auth`;
    return { url: `${base}?${params.toString()}`, pkce };
  }

  /** Exchange an authorization code for tokens and verify the ID token. */
  async exchangeCode(opts: { code: string; codeVerifier: string; nonce?: string }): Promise<TokenSet> {
    const disc = await this.discover();
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: opts.code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      code_verifier: opts.codeVerifier,
    });
    const tok = (await this.postForm(disc.token_endpoint, body)) as {
      id_token: string;
      access_token: string;
      refresh_token?: string;
    };
    return this.finishTokens(tok, opts.nonce);
  }

  /** Refresh with a rotating refresh token. */
  async refresh(refreshToken: string): Promise<TokenSet> {
    const disc = await this.discover();
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.config.clientId,
    });
    const tok = (await this.postForm(disc.token_endpoint, body)) as {
      id_token: string;
      access_token: string;
      refresh_token?: string;
    };
    return this.finishTokens(tok);
  }

  private async finishTokens(
    tok: { id_token: string; access_token: string; refresh_token?: string },
    nonce?: string,
  ): Promise<TokenSet> {
    const jwks = await this.getJwks();
    const claims = verifyIdToken(tok.id_token, {
      issuer: ID.issuer,
      audience: this.config.clientId,
      jwks,
      ...(nonce !== undefined ? { nonce } : {}),
    });
    return {
      idToken: tok.id_token,
      accessToken: tok.access_token,
      ...(tok.refresh_token !== undefined ? { refreshToken: tok.refresh_token } : {}),
      claims,
    };
  }

  /** POST /siwe/challenge — EIP-4361 message + single-use nonce. */
  async siweChallenge(address: string): Promise<{ message: string; nonce: string }> {
    return (await this.postJson(`${ID.issuer}/siwe/challenge`, { address })) as { message: string; nonce: string };
  }

  /** POST /siwe/verify — returns an ID token on success. */
  async siweVerify(opts: { message: string; signature: string }): Promise<TokenSet> {
    const tok = (await this.postJson(`${ID.issuer}/siwe/verify`, opts)) as {
      id_token: string;
      access_token: string;
      refresh_token?: string;
    };
    return this.finishTokens(tok);
  }

  /** GET /userinfo — fresh claims + normalized entitlement capabilities. */
  async userInfo(accessToken: string): Promise<UserInfo> {
    const disc = await this.discover();
    const raw = (await this.getJson(disc.userinfo_endpoint, accessToken)) as Record<string, unknown>;
    const entitlement = raw[ID.entitlementClaim] as
      | { tier?: unknown; citrateRole?: string; expiresAt?: number | null }
      | undefined;
    const tier = normalizeTier(entitlement?.tier);
    // SJS-B-001 was: `{ecosystemTx,gatewayKeys,academicData,confidentialDocs}: true` for ANY
    // truthy `citrateRole`, granting confidential access to any role at any tier.
    // SJS-B-002: this inline copy also omitted the `expiresAt` fail-safe that `can()` honours,
    // so an expired claim kept full capabilities here while `can()` collapsed it to public — one
    // policy, two answers. Route through the single canonical resolver (`resolveCapabilities`,
    // the same one `can` uses) so a role escalates only via the ROLE_CAPABILITIES allowlist AND
    // an expired claim collapses to public — no inline duplicate, no divergence on expiry.
    return {
      sub: String(raw['sub'] ?? ''),
      ...(typeof raw['wallet_address'] === 'string' ? { walletAddress: raw['wallet_address'] } : {}),
      ...(Array.isArray(raw['wallets']) ? { wallets: raw['wallets'] as string[] } : {}),
      ...(typeof raw['kyc_status'] === 'string' ? { kycStatus: raw['kyc_status'] } : {}),
      tier,
      capabilities: resolveCapabilities(entitlement),
      raw,
    };
  }

  /**
   * Request a factory deploy permit for the embedded wallet (authenticated).
   * POST /aa/enroll-validator — the authority signs with its identity-signer; the SDK never signs.
   * The returned permit is what the user includes in the CitrateWalletFactory.deployFor call.
   */
  async requestDeployPermit(
    opts: { userId: string; initData: string; expiresAt: number },
    accessToken: string,
  ): Promise<DeployPermit> {
    return (await this.postJson(`${ID.issuer}/aa/enroll-validator`, opts, accessToken)) as DeployPermit;
  }

  /** GET /aa/validators — the validators installed on the wallet (chain read, no auth). */
  async listValidators(userId: string): Promise<unknown> {
    return this.getJson(`${ID.issuer}/aa/validators?userId=${encodeURIComponent(userId)}`);
  }

  /** GET /aa/guardians — the caller's stored guardian nomination + Kernel initConfig (Bearer). */
  async guardianConfig(accessToken: string): Promise<unknown> {
    return this.getJson(`${ID.issuer}/aa/guardians`, accessToken);
  }

  /** POST end_session/logout — fires the cross-instance revocation cascade. */
  async logout(accessToken: string): Promise<void> {
    const disc = await this.discover().catch(() => undefined);
    const url = disc?.end_session_endpoint ?? `${ID.issuer}/logout`;
    await this.postForm(url, new URLSearchParams(), accessToken);
  }

  // ── transport helpers ───────────────────────────────────────────────────────
  private async getJson(url: string, bearer?: string): Promise<unknown> {
    const res = await this.fetch(url, { method: 'GET', headers: bearer ? { authorization: `Bearer ${bearer}` } : {} });
    if (!res.ok) throw new IdentityError(`GET ${url} failed: ${res.status}`, res.status);
    return res.json();
  }

  private async postForm(url: string, body: URLSearchParams, bearer?: string): Promise<unknown> {
    const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
    if (bearer) headers['authorization'] = `Bearer ${bearer}`;
    const res = await this.fetch(url, { method: 'POST', headers, body: body.toString() });
    if (!res.ok) throw new IdentityError(`POST ${url} failed: ${res.status}`, res.status);
    return res.status === 204 ? {} : res.json();
  }

  private async postJson(url: string, obj: unknown, bearer?: string): Promise<unknown> {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (bearer) headers['authorization'] = `Bearer ${bearer}`;
    const res = await this.fetch(url, { method: 'POST', headers, body: JSON.stringify(obj) });
    if (!res.ok) throw new IdentityError(`POST ${url} failed: ${res.status}`, res.status);
    return res.json();
  }
}
