/**
 * PBA-L4-001 tripwire: does a piece of public deploy calldata reveal the model
 * AES key?
 *
 * This module is deliberately independent of the SDK code under test. It has
 * its own GF(2^8) arithmetic (AES polynomial 0x11b, the one `FiniteField.ts`
 * uses) and its own Lagrange interpolation, and it does no share validation.
 * A regression in the SDK's Shamir code can therefore neither hide a leak nor
 * fake a pass here.
 *
 * `revealsKey(calldata, key)` answers "can an observer who only has the
 * calldata rebuild the key?" It tries three things:
 *   1. the key bytes appear verbatim (hex, 0x-hex or base64) anywhere;
 *   2. explicit share objects ({x, y}) anywhere in the decoded JSON: every
 *      subset of them is interpolated at x = 0;
 *   3. bare key-length hex strings anywhere (candidate share y values with the
 *      x stripped): every subset of up to MAX_BARE_SUBSET of them, under every
 *      assignment of x in 1..MAX_BARE_X, is interpolated at x = 0.
 * Nested JSON strings (the SDK JSON-encodes envelopes inside JSON) are parsed
 * recursively.
 *
 * Used by tests/unit/pba_r2_l4_keyshares.test.ts (against src/) and by
 * scripts/check-keyshare-pack.mjs (against the packed npm tarball).
 */
'use strict';

const MAX_EXPLICIT_SUBSET = 8;
const MAX_BARE_SUBSET = 3;
const MAX_BARE_X = 8;

function gfMul(a, b) {
  let p = 0;
  a &= 0xff;
  b &= 0xff;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

function gfInv(a) {
  if ((a & 0xff) === 0) return null;
  let r = 1;
  for (let i = 0; i < 254; i++) r = gfMul(r, a);
  return r;
}

/** Interpolate f(0) byte-wise. Returns null if the points are degenerate. */
function interpolateAtZero(points) {
  const len = points[0].y.length;
  if (!points.every((p) => p.y.length === len)) return null;
  const xs = points.map((p) => p.x);
  if (new Set(xs).size !== xs.length) return null;
  const out = new Uint8Array(len);
  for (let i = 0; i < points.length; i++) {
    let num = 1;
    let den = 1;
    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      num = gfMul(num, xs[j]);
      den = gfMul(den, xs[i] ^ xs[j]);
    }
    const inv = gfInv(den);
    if (inv === null) return null;
    const li = gfMul(num, inv);
    for (let b = 0; b < len; b++) out[b] ^= gfMul(points[i].y[b], li);
  }
  return out;
}

function hexToBytes(h) {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function bytesToHex(b) {
  return Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
}

function eq(a, b) {
  if (!a || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function* subsets(arr, maxSize) {
  const n = arr.length;
  const limit = Math.min(maxSize, n);
  function* rec(start, size, acc) {
    if (acc.length === size) {
      yield acc.slice();
      return;
    }
    for (let i = start; i < n; i++) {
      acc.push(arr[i]);
      yield* rec(i + 1, size, acc);
      acc.pop();
    }
  }
  for (let size = 1; size <= limit; size++) yield* rec(0, size, []);
}

/** Walk a decoded value; collect explicit {x,y} shares and every string. */
function walk(value, explicit, strings, depth) {
  if (depth > 16 || value === null || value === undefined) return;
  if (typeof value === 'string') {
    strings.push(value);
    const t = value.trim();
    if ((t.startsWith('{') || t.startsWith('[')) && t.length < 1_000_000) {
      try {
        walk(JSON.parse(t), explicit, strings, depth + 1);
      } catch {
        /* not JSON */
      }
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) walk(v, explicit, strings, depth + 1);
    return;
  }
  if (typeof value === 'object') {
    const x = Number(value.x);
    if (value.y !== undefined && Number.isInteger(x)) {
      const y = typeof value.y === 'string' ? hexToBytes(value.y) : null;
      if (y) explicit.push({ x: x & 0xff, y });
    }
    for (const k of Object.keys(value)) walk(value[k], explicit, strings, depth + 1);
  }
}

/**
 * @param {string} calldata  the transaction `data` (0x-hex of UTF-8 JSON) or the
 *                           decoded UTF-8 text itself
 * @param {Uint8Array} key   the real model key (known to the test only)
 * @returns {{ reveals: boolean, how?: string }}
 */
function revealsKey(calldata, key) {
  let text = calldata;
  if (/^0x[0-9a-fA-F]*$/.test(calldata)) {
    const raw = hexToBytes(calldata);
    text = Buffer.from(raw).toString('utf8');
  }
  const keyHex = bytesToHex(key);
  const keyB64 = Buffer.from(key).toString('base64');
  if (text.toLowerCase().includes(keyHex) || text.includes(keyB64)) {
    return { reveals: true, how: 'key bytes appear verbatim' };
  }

  const explicit = [];
  const strings = [];
  let root;
  try {
    root = JSON.parse(text);
  } catch {
    root = text;
  }
  walk(root, explicit, strings, 0);

  for (const subset of subsets(explicit, MAX_EXPLICIT_SUBSET)) {
    if (eq(interpolateAtZero(subset), key)) {
      return { reveals: true, how: `explicit shares x=${subset.map((s) => s.x).join(',')}` };
    }
  }

  // Bare candidates: any hex run of exactly key length, standalone or embedded.
  const want = key.length * 2;
  const seen = new Set();
  const bare = [];
  const re = new RegExp(`(?:0x)?([0-9a-fA-F]{${want}})(?![0-9a-fA-F])`, 'g');
  for (const s of strings) {
    for (const m of s.matchAll(re)) {
      const h = m[1].toLowerCase();
      if (seen.has(h)) continue;
      seen.add(h);
      bare.push(hexToBytes(h));
    }
  }
  for (const subset of subsets(bare, MAX_BARE_SUBSET)) {
    const k = subset.length;
    const xs = new Array(k).fill(1);
    for (;;) {
      const pts = subset.map((y, i) => ({ x: xs[i], y }));
      if (eq(interpolateAtZero(pts), key)) {
        return { reveals: true, how: `bare key-length values at x=${xs.join(',')}` };
      }
      let i = 0;
      while (i < k && xs[i] === MAX_BARE_X) xs[i++] = 1;
      if (i === k) break;
      xs[i]++;
    }
  }
  return { reveals: false };
}

module.exports = { revealsKey, interpolateAtZero };
