/**
 * RM-Q tripwires — citrate-sdk-js HIGH findings (Leg B).
 *
 * SJS-B-001: the canonical entitlement gate granted EVERY capability (incl.
 *   `confidentialDocs`) to ANY principal carrying a non-empty `citrateRole`, with no
 *   allowlist and no reference to tier — `if (claim.citrateRole) return true;`. The same
 *   policy was re-implemented inline in `IdentityClient.userInfo`.
 * SJS-B-002: `IdentityClient.userInfo` re-implemented the capability decision inline and
 *   omitted the `expiresAt` fail-safe that `can()` honours, so an expired entitlement kept
 *   full capabilities through the identity spine.
 *
 * RC-8: these assertions were authored against the fixed code. Run RED against the parent
 * (pre-fix) commit they fail — a truthy role escalates to `confidentialDocs`, and an expired
 * claim keeps full caps through `userInfo` — which is the point. The matrix tripwires bind
 * `userInfo` to `can()` so the two policy paths can never diverge again.
 */
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

import { FEDERATION_CONTRACT } from '../../src/generated/contract';
import {
  can,
  capabilities,
  type Capability,
  type CapabilitySet,
  type EntitlementClaimLike,
} from '../../src/entitlements/capabilities';
import { IdentityClient, type FetchLike } from '../../src/identity/client';
import type { Jwk } from '../../src/identity/jwt';

const CAPS: readonly Capability[] = ['ecosystemTx', 'gatewayKeys', 'academicData', 'confidentialDocs'];

// ── SJS-B-001: an unrecognised citrateRole must NOT escalate ──────────────────────────────
describe('SJS-B-001 — citrateRole is not a blanket capability bypass', () => {
  it('a public-tier principal with an unknown role does NOT gain confidentialDocs', () => {
    expect(can({ tier: 'public', citrateRole: 'viewer' }, 'confidentialDocs')).toBe(false);
    expect(can({ tier: 'public', citrateRole: 'intern' }, 'confidentialDocs')).toBe(false);
    expect(can({ tier: 'public', citrateRole: 'guest' }, 'confidentialDocs')).toBe(false);
    // the numeric-string curio from the finding — truthy, must still not escalate
    expect(can({ citrateRole: '0e0' }, 'gatewayKeys')).toBe(false);
  });

  it('an unrecognised role escalates NO capability — it falls back to the tier', () => {
    for (const cap of CAPS) {
      expect(can({ tier: 'public', citrateRole: 'nonsense' }, cap)).toBe(
        capabilities('public')[cap],
      );
      // a garbage tier with a role must not reach confidential either
      expect(can({ tier: 'made-up', citrateRole: 'x' }, cap)).toBe(capabilities('made-up')[cap]);
    }
  });

  it('the tier alone still confers its capabilities when a role is present', () => {
    // a confidential principal keeps confidential caps regardless of any role string
    expect(can({ tier: 'confidential', citrateRole: 'anything' }, 'confidentialDocs')).toBe(true);
  });
});

// ── SJS-B-002 + SJS-B-001 through the identity spine ──────────────────────────────────────
const ID = FEDERATION_CONTRACT.identity;
const CLIENT_ID = 'citrate-core';
const KID = 'kid-1';
const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const JWKS: Jwk[] = [{ ...(publicKey.export({ format: 'jwk' }) as Jwk), kid: KID, use: 'sig', alg: 'RS256' }];

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

function makeFetch(userinfoBody: Record<string, unknown>): FetchLike {
  return (url) => {
    if (url === ID.discovery) return ok(discovery);
    if (url === discovery.jwks_uri) return ok({ keys: JWKS });
    if (url === discovery.userinfo_endpoint) return ok(userinfoBody);
    return Promise.resolve({ ok: false, status: 404, json: async () => ({}), text: async () => 'not found' });
  };
}

async function capsFor(entitlement: Record<string, unknown>): Promise<CapabilitySet> {
  const body = { sub: 'u', [ID.entitlementClaim]: entitlement };
  const client = new IdentityClient({ clientId: CLIENT_ID, redirectUri: 'x', fetch: makeFetch(body) });
  return (await client.userInfo('at-1')).capabilities;
}

describe('SJS-B-002 — userInfo honours expiresAt, exactly as can() does', () => {
  it('an expired confidential claim collapses to public through the identity spine', async () => {
    const expired = Date.now() - 86_400_000; // 24h ago
    // can() correctly collapses it — the reference behaviour
    expect(can({ tier: 'confidential', expiresAt: expired }, 'confidentialDocs')).toBe(false);
    // and the identity spine must agree
    const caps = await capsFor({ tier: 'confidential', expiresAt: expired });
    expect(caps.confidentialDocs).toBe(false);
    expect(caps).toEqual(capabilities('public'));
  });

  it('a non-expired confidential claim keeps its capabilities', async () => {
    const future = Date.now() + 86_400_000;
    const caps = await capsFor({ tier: 'confidential', expiresAt: future });
    expect(caps.confidentialDocs).toBe(true);
  });
});

describe('SJS-B-001 — userInfo does not blanket-escalate on a role', () => {
  it('a public-tier principal with an unknown role gets public capabilities', async () => {
    const caps = await capsFor({ tier: 'public', citrateRole: 'auditor' });
    expect(caps.confidentialDocs).toBe(false);
    expect(caps).toEqual(capabilities('public'));
  });
});

describe('userInfo capabilities equal can() for a matrix of claims (the two paths cannot diverge)', () => {
  const claims: EntitlementClaimLike[] = [
    { tier: 'public' },
    { tier: 'commercial' },
    { tier: 'commercial.kyc' },
    { tier: 'academic' },
    { tier: 'confidential' },
    { tier: 'made-up' },
    { tier: 'public', citrateRole: 'auditor' },
    { tier: 'confidential', citrateRole: 'exec' },
    { tier: 'confidential', expiresAt: Date.now() - 1_000 },
    { tier: 'academic', expiresAt: Date.now() + 1_000 },
  ];

  it.each(claims)('userInfo caps == can() per capability for %o', async (claim) => {
    const caps = await capsFor(claim as Record<string, unknown>);
    for (const cap of CAPS) {
      expect(caps[cap]).toBe(can(claim, cap));
    }
  });
});
