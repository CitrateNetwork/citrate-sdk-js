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
/**
 * Deliberately LENIENT y match, a superset of the strict parser
 * (CryptoManager.hexToBytes) and of lenient decoders elsewhere: after removing
 * whitespace, any run of >= 16 bytes of hex digits counts.
 */
const SHARE_Y_HEX_RUN = new RegExp(`[0-9a-fA-F]{${2 * MIN_SHARE_BYTES},}`);
function shareYLike(y: string): boolean {
  return SHARE_Y_HEX_RUN.test(y.replace(/\s+/g, ''));
}

function isShareX(x: unknown): boolean {
  if (typeof x === 'number') return Number.isInteger(x) && x >= 1 && x <= 255;
  return typeof x === 'string' && /^[0-9]{1,3}$/.test(x) && Number(x) >= 1 && Number(x) <= 255;
}

function isByteInt(v: unknown): boolean {
  // Signed (Int8Array) or unsigned byte values.
  return typeof v === 'number' && Number.isInteger(v) && v >= -128 && v <= 255;
}

/**
 * Length of `y` if it is bytes or a JSON rendering of bytes (an integer
 * array, the `{type: 'Buffer', data: [...]}` shape, or an object keyed
 * "0".."n-1" with byte values); otherwise 0.
 */
function bytesLikeLength(y: unknown): number {
  if (y instanceof Uint8Array) return y.length;
  if (y !== null && typeof y === 'object') {
    // Arrays are covered by the index-keyed branch (their keys are "0".."n-1").
    const o = y as Record<string, unknown>;
    const keys = Object.keys(o);
    if (o['type'] === 'Buffer' && Array.isArray(o['data'])) return bytesLikeLength(o['data']);
    if (keys.length > 0 && keys.every((k, i) => k === String(i)) && keys.every((k) => isByteInt(o[k]))) return keys.length;
  }
  return 0;
}

/**
 * True if a valid JSON text contains an object with a repeated key. JSON.parse
 * keeps the last value, so duplicate keys are refused rather than resolved.
 */
export function hasDuplicateJsonKeys(text: string): boolean {
  const stack: Array<{ keys: Set<string> | null; expectKey: boolean }> = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '{') stack.push({ keys: new Set(), expectKey: true });
    else if (c === '[') stack.push({ keys: null, expectKey: false });
    else if (c === '}' || c === ']') stack.pop();
    else if (c === ',') {
      const top = stack[stack.length - 1];
      if (top && top.keys) top.expectKey = true;
    } else if (c === ':') {
      const top = stack[stack.length - 1];
      if (top) top.expectKey = false;
    } else if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top && top.keys && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.keys.has(key)) return true;
        top.keys.add(key);
      }
      i = j;
    }
  }
  return false;
}

const DUP_MSG =
  'deployModel: refusing to publish JSON with duplicate object keys; decoders disagree on which ' +
  'value wins, so the content cannot be checked for key-share material (PBA-L4-001).';

/**
 * Guard a serialised JSON payload exactly as it will be sent: parse it
 * (refusing duplicate keys) and run {@link assertNoKeyShareMaterial}.
 */
export function assertPayloadHasNoKeyShareMaterial(wire: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(wire);
  } catch {
    throw new CitrateError('deployModel: payload is not valid JSON; refusing to publish it.');
  }
  if (hasDuplicateJsonKeys(wire)) throw new CitrateError(DUP_MSG);
  assertNoKeyShareMaterial(parsed);
}

/**
 * A raw Shamir share ({x in 1..255, y of share length as hex or bytes}) or a
 * holder-wrapped share record. Short or coordinate-like values are not shares.
 */
function looksLikeShare(o: Record<string, unknown>): boolean {
  const xs = ['x', 'X'].filter((k) => k in o).map((k) => o[k]);
  const ys = ['y', 'Y'].filter((k) => k in o).map((k) => o[k]);
  if (xs.some(isShareX)) {
    for (const y of ys) {
      if (bytesLikeLength(y) >= MIN_SHARE_BYTES) return true;
      if (typeof y === 'string' && shareYLike(y)) return true;
    }
  }
  return 'envelope' in o && ('holderPublicKey' in o || 'holder_public_key' in o);
}

/**
 * Refuses the known share field names AND, by structure, any value shaped like
 * a share or a wrapped share record, at any depth and inside JSON-encoded
 * strings, so a renamed field (e.g. `myShares`) is caught too.
 */
export function assertNoKeyShareMaterial(value: unknown, depth = 0): void {
  if (depth === 0 && value !== null && typeof value === 'object') {
    // Also check the serialised form. Callers that send data should also run
    // assertPayloadHasNoKeyShareMaterial on the exact bytes they send.
    let wire: unknown;
    try {
      wire = JSON.parse(JSON.stringify(value));
    } catch {
      wire = undefined;
    }
    if (wire !== undefined) scan(wire, depth);
  }
  scan(value, depth);
}

function scan(value: unknown, depth: number): void {
  if (typeof value === 'string') {
    // Any string that parses as JSON is checked too: a share can be smuggled
    // as a JSON-encoded blob inside an ordinary-looking field.
    let decoded: unknown;
    try {
      decoded = JSON.parse(value);
    } catch {
      return;
    }
    if (hasDuplicateJsonKeys(value)) throw new CitrateError(DUP_MSG);
    scan(decoded, depth + 1);
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
    scan(v, depth + 1);
  }
}
