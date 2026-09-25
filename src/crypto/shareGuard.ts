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

/** A share's y is at least 16 bytes (the SDK shares 32-byte keys). */
const MIN_SHARE_BYTES = 16;
const SHARE_Y_HEX = /^(0x)?(?:[0-9a-fA-F]{2}){16,}$/;

function isShareX(x: unknown): boolean {
  if (typeof x === 'number') return Number.isInteger(x) && x >= 1 && x <= 255;
  return typeof x === 'string' && /^[0-9]{1,3}$/.test(x) && Number(x) >= 1 && Number(x) <= 255;
}

/**
 * A raw Shamir share ({x in 1..255, y of share length as hex or bytes}) or a
 * holder-wrapped share record. Short or coordinate-like values are not shares.
 */
function looksLikeShare(o: Record<string, unknown>): boolean {
  const y = o['y'];
  if ('x' in o && isShareX(o['x'])) {
    if (y instanceof Uint8Array && y.length >= MIN_SHARE_BYTES) return true;
    if (typeof y === 'string' && SHARE_Y_HEX.test(y)) return true;
  }
  return 'envelope' in o && ('holderPublicKey' in o || 'holder_public_key' in o);
}

/**
 * Refuses the known share field names AND, by structure, any value shaped like
 * a share or a wrapped share record, at any depth and inside JSON-encoded
 * strings, so a renamed field (e.g. `myShares`) is caught too.
 */
export function assertNoKeyShareMaterial(value: unknown, depth = 0): void {
  if (typeof value === 'string') {
    // Any string that parses as JSON is checked too: a share can be smuggled
    // as a JSON-encoded blob inside an ordinary-looking field.
    let decoded: unknown;
    try {
      decoded = JSON.parse(value);
    } catch {
      return;
    }
    assertNoKeyShareMaterial(decoded, depth + 1);
    return;
  }
  if (value === null || typeof value !== 'object' || value instanceof Uint8Array) return;
  if (depth > MAX_DEPTH) {
    throw new CitrateError(
      `deployModel: metadata is nested more than ${MAX_DEPTH} levels deep; refusing to publish ` +
        'calldata that cannot be fully checked for key-share material (PBA-L4-001).'
    );
  }
  if (!Array.isArray(value) && looksLikeShare(value as Record<string, unknown>)) {
    throw new CitrateError(
      'deployModel: refusing to publish a value shaped like a key share ({x, y} or a wrapped ' +
        'share record) in public deploy calldata. Deliver key shares to their holders off-chain (PBA-L4-001).'
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
