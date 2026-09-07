/**
 * DEVX-S2 / F3 — entitlements as capabilities, not a global rank (ADR-0002).
 * Ends the federation-wide disagreement over what commercial.kyc means.
 */
import {
  can,
  capabilities,
  DEFAULT_CAPABILITIES,
  normalizeTier,
  TIERS,
} from '../../src/entitlements/capabilities';

describe('normalizeTier — fail-safe, never escalates', () => {
  it('passes through the five known tiers', () => {
    for (const t of TIERS) expect(normalizeTier(t)).toBe(t);
  });

  it('collapses unknown / garbage / non-string to public', () => {
    expect(normalizeTier('totally-made-up')).toBe('public');
    expect(normalizeTier('confidential.super')).toBe('public');
    expect(normalizeTier(undefined)).toBe('public');
    expect(normalizeTier(42)).toBe('public');
    expect(normalizeTier({ tier: 'confidential' })).toBe('public');
  });
});

describe('commercial.kyc opens transactions, not content (the canonical answer)', () => {
  it('grants ecosystemTx but NOT confidentialDocs', () => {
    const caps = capabilities('commercial.kyc');
    expect(caps.ecosystemTx).toBe(true);
    expect(caps.gatewayKeys).toBe(true);
    expect(caps.confidentialDocs).toBe(false);
    expect(caps.academicData).toBe(false);
  });

  it('is not "above" commercial — same content capabilities, no ordinal', () => {
    expect(capabilities('commercial.kyc')).toEqual(capabilities('commercial'));
  });

  it('only confidential unlocks confidentialDocs', () => {
    expect(DEFAULT_CAPABILITIES.confidential.confidentialDocs).toBe(true);
    expect(DEFAULT_CAPABILITIES.academic.confidentialDocs).toBe(false);
    expect(DEFAULT_CAPABILITIES.public.confidentialDocs).toBe(false);
  });
});

describe('can() — expiry + role bypass semantics', () => {
  it('public claim cannot read confidential', () => {
    expect(can({ tier: 'public' }, 'confidentialDocs')).toBe(false);
  });

  it('an unallowlisted role does NOT bypass the gate (SJS-B-001 — no blanket escalation)', () => {
    // Was `.toBe(true)`: any truthy citrateRole granted confidentialDocs at any tier. A role
    // absent from ROLE_CAPABILITIES now derives capabilities from the tier — public here.
    expect(can({ tier: 'public', citrateRole: 'auditor' }, 'confidentialDocs')).toBe(false);
  });

  it('an expired claim collapses to public', () => {
    const past = 1_000; // epoch-ms in the distant past
    expect(can({ tier: 'confidential', expiresAt: past }, 'confidentialDocs', { now: 2_000 })).toBe(false);
  });

  it('null claim is public', () => {
    expect(can(null, 'ecosystemTx')).toBe(false);
  });

  it('an RP can override the default map', () => {
    const overrides = { 'commercial.kyc': { ...DEFAULT_CAPABILITIES['commercial.kyc'], confidentialDocs: true } };
    expect(can({ tier: 'commercial.kyc' }, 'confidentialDocs', { overrides })).toBe(true);
  });
});
