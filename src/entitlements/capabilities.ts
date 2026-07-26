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
 * Whether a claim grants a capability. Applies the same fail-safe + role-bypass semantics as
 * the authority's `resolveEntitlementClaim`: an expired claim is `public`; a role-bearing
 * principal is granted the capability regardless of tier.
 */
export function can(
  claim: EntitlementClaimLike | null | undefined,
  capability: Capability,
  opts?: { now?: number; overrides?: Partial<Record<Tier, CapabilitySet>> },
): boolean {
  if (!claim) return DEFAULT_CAPABILITIES.public[capability];
  const now = opts?.now ?? Date.now();
  if (typeof claim.expiresAt === 'number' && claim.expiresAt <= now) {
    return DEFAULT_CAPABILITIES.public[capability];
  }
  if (claim.citrateRole) return true; // role bypass — matches resolveEntitlementClaim
  return capabilities(claim.tier, opts?.overrides)[capability];
}
