/**
 * PBA-L4-001 guard: deploy calldata is public and must never carry key-share
 * material. `deployModel` runs this over the whole transaction payload,
 * including caller-supplied metadata, right before sending.
 */
import { CitrateError } from '../errors/CitrateError';

/** Field names that only ever hold Shamir share material. */
export const SHARE_FIELD_DENYLIST: readonly string[] = ['keyShares', 'key_shares', 'keyShareEnvelopes', 'key_share_envelopes'];

/** Deeper payloads are refused rather than partially scanned. */
const MAX_DEPTH = 32;

export function assertNoKeyShareMaterial(value: unknown, depth = 0): void {
  if (value === null || typeof value !== 'object') return;
  if (depth > MAX_DEPTH) {
    throw new CitrateError(
      `deployModel: metadata is nested more than ${MAX_DEPTH} levels deep; refusing to publish ` +
        'calldata that cannot be fully checked for key-share material (PBA-L4-001).'
    );
  }
  // Object.entries covers arrays too (index keys).
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (SHARE_FIELD_DENYLIST.includes(k)) {
      throw new CitrateError(
        `deployModel: refusing to publish key-share material ('${k}') in public deploy calldata. ` +
          'Deliver key shares to their holders off-chain (PBA-L4-001).'
      );
    }
    assertNoKeyShareMaterial(v, depth + 1);
  }
}
