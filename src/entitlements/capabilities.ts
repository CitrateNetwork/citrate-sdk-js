/**
 * Entitlement capabilities (DEVX-S2, ADR-0002).
 *
 * The federation ships ONE canonical way to read the `https://citrate.ai/entitlement`
 * claim, so RPs stop disagreeing about what a tier means (the bug where Atlas ranked
 * `commercial.kyc` as public while explorer/memories ranked it above `commercial`).
 *
 * The design is CAPABILITIES, NOT A GLOBAL RANK. There is no `tier >= otherTier` anywhere.
 * `normalizeTier` collapses any unknown value to `public` and never escalates; `capabilities`
 * returns an explicit capability set. RPs that need different gating pass an override map,
 * but the canonical default exists so the federation stops diverging by accident.
 */
import type { EntitlementTier } from '../generated/contract';

export type Tier = EntitlementTier;

/** The five tiers the authority mints (mirrors citrate-identity `TIERS`). */
export const TIERS: readonly Tier[] = [
  'public',
  'commercial',
  'commercial.kyc',
  'academic',
  'confidential',
];

/** What a principal may do. Explicit set membership — never derived from an ordering. */
export interface CapabilitySet {
  /** Transact in the ecosystem (the thing KYC opens). */
  ecosystemTx: boolean;
  /** Mint inference-gateway (`cgk_`) keys. */
  gatewayKeys: boolean;
  /** Read academic-tier datasets. */
  academicData: boolean;
  /** Read confidential-tier content/docs. */
  confidentialDocs: boolean;
}

export type Capability = keyof CapabilitySet;

const NONE: CapabilitySet = {
  ecosystemTx: false,
  gatewayKeys: false,
  academicData: false,
  confidentialDocs: false,
};

/**
 * The canonical default tier→capability map.
 * KEY DECISION (ADR-0002): `commercial.kyc` opens ecosystem transactions but NOT
 * confidential content — passing KYC does not buy a docs seat (owner's call 2026-07-24).
 * `commercial.kyc` is NOT "above" `commercial`; it is the KYC-verified baseline with the
 * same content capabilities. No ordinal is implied.
 */
export const DEFAULT_CAPABILITIES: Readonly<Record<Tier, CapabilitySet>> = {
  public: { ...NONE },
  commercial: { ...NONE, ecosystemTx: true, gatewayKeys: true },
  'commercial.kyc': { ...NONE, ecosystemTx: true, gatewayKeys: true },
  academic: { ...NONE, ecosystemTx: true, gatewayKeys: true, academicData: true },
  confidential: { ecosystemTx: true, gatewayKeys: true, academicData: true, confidentialDocs: true },
};

const TIER_SET: ReadonlySet<string> = new Set(TIERS);

/**
 * EXPLICIT allowlist of `citrateRole` values that carry capabilities beyond the principal's
 * tier, replacing the blanket `if (claim.citrateRole) return true;` bypass that granted EVERY
 * capability — including `confidentialDocs` — to ANY truthy role, at ANY tier (SJS-B-001).
 *
 * A role absent from this map does NOT escalate: capabilities fall back to the tier — the same
 * fail-safe `normalizeTier` applies to unknown tiers. The authority's `resolveEntitlementClaim`
 * (citrate-identity src/entitlements.ts) uses `citrateRole` only to exempt a principal from the
 * consumer-KYC *downgrade*; the tier it returns is what confers capabilities, so a role never
 * itself buys confidential access. The canonical default is therefore EMPTY. A relying party
 * that genuinely elevates a specific role registers it here explicitly.
 */
export const ROLE_CAPABILITIES: Readonly<Record<string, CapabilitySet>> = {};

/**
 * Normalize an entitlement tier value at the trust boundary. Unknown/garbage collapses to
 * `public` and is NEVER escalated — the fail-safe that would have prevented the Atlas crash.
 */
export function normalizeTier(value: unknown): Tier {
  return typeof value === 'string' && TIER_SET.has(value) ? (value as Tier) : 'public';
}

/** The minimal shape of the entitlement claim this module reads. */
export interface EntitlementClaimLike {
  tier?: unknown;
  /** A role-bearing principal (admin/auditor/exec/…) bypasses the KYC/content gates. */
  citrateRole?: string | null;
  /** epoch-ms; access past this instant collapses to public. */
  expiresAt?: number | null;
}

/** Capabilities for a raw tier value (normalized first). */
export function capabilities(
  tier: unknown,
  overrides?: Partial<Record<Tier, CapabilitySet>>,
): CapabilitySet {
  const t = normalizeTier(tier);
  return { ...(overrides?.[t] ?? DEFAULT_CAPABILITIES[t]) };
}

/**
 * Resolve a claim's capability set WITHOUT applying expiry.
 *
 * An allowlisted `citrateRole` (see `ROLE_CAPABILITIES`) grants its explicitly declared set;
 * every other role — and no role — derives capabilities from the tier, fail-safe and never
 * escalated (SJS-B-001). Expiry is NOT applied here; callers that must honour `expiresAt` use
 * `resolveCapabilities`/`can`, which check it before delegating. This is the single resolver
 * both `can` and the identity spine use, so the role policy cannot diverge between them.
 */
export function capabilitiesForClaim(
  claim: EntitlementClaimLike | null | undefined,
  overrides?: Partial<Record<Tier, CapabilitySet>>,
): CapabilitySet {
  if (!claim) return { ...DEFAULT_CAPABILITIES.public };
  const role = claim.citrateRole;
  if (typeof role === 'string') {
    const roleCaps = ROLE_CAPABILITIES[role];
    if (roleCaps) return { ...roleCaps };
  }
  return capabilities(claim.tier, overrides);
}

/**
 * Resolve a claim's FULL capability set, honouring `expiresAt`.
 *
 * THE single policy implementation. Both `can` and the identity spine (`IdentityClient.userInfo`)
 * route through it, so the expiry check cannot be present on one path and absent on the other
 * (SJS-B-002): an expired claim collapses to `public` here, once, for every caller. Role
 * escalation stays gated by the `ROLE_CAPABILITIES` allowlist via `capabilitiesForClaim`.
 */
export function resolveCapabilities(
  claim: EntitlementClaimLike | null | undefined,
  opts?: { now?: number; overrides?: Partial<Record<Tier, CapabilitySet>> },
): CapabilitySet {
  if (!claim) return { ...DEFAULT_CAPABILITIES.public };
  const now = opts?.now ?? Date.now();
  if (typeof claim.expiresAt === 'number' && claim.expiresAt <= now) {
    return { ...DEFAULT_CAPABILITIES.public };
  }
  return capabilitiesForClaim(claim, opts?.overrides);
}

/**
 * Whether a claim grants a capability. A thin projection of `resolveCapabilities` onto one
 * capability — the same resolver the identity spine uses, so the two cannot diverge. An expired
 * claim collapses to `public`; a `citrateRole` escalates only if it is in the `ROLE_CAPABILITIES`
 * allowlist (matches `resolveEntitlementClaim`, which uses the role only to skip the KYC
 * downgrade, never to confer confidential access).
 */
export function can(
  claim: EntitlementClaimLike | null | undefined,
  capability: Capability,
  opts?: { now?: number; overrides?: Partial<Record<Tier, CapabilitySet>> },
): boolean {
  return resolveCapabilities(claim, opts)[capability];
}
