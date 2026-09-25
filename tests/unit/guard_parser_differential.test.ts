/**
 * Differential property test: share guard versus share parsers (JS).
 *
 * Generates near-hex strings from a fixed seed (canonical hex, perturbed hex,
 * free-form near-hex with ASCII/Unicode whitespace, junk characters and 0x/0X
 * prefixes) and checks on every input:
 *   1. CryptoManager.hexToBytes agrees with a reference strict grammar
 *      (a lenient parser fails this);
 *   2. anything the strict reference, a Python bytes.fromhex-style decoder or
 *      the legacy truncating JS decoder turns into >= 16 bytes is refused by
 *      the guard (a canonical-only guard fails this).
 */
import { CryptoManager } from '../../src/crypto/CryptoManager';
import { assertNoKeyShareMaterial } from '../../src/crypto/shareGuard';

const N = 40_000;
const MIN = 16;
const HEX = '0123456789abcdefABCDEF';
const WS = [' ', '\t', '\n', '\r', ' ', ' ', '　'];
const JUNK = ['z', 'g', 'x', 'X', '-', ':', '１', '.'];

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = <T>(r: () => number, xs: readonly T[] | string): T => xs[Math.floor(r() * xs.length)] as T;
const int = (r: () => number, lo: number, hi: number) => lo + Math.floor(r() * (hi - lo + 1));

function gen(r: () => number): string {
  const pairs = Array.from({ length: int(r, 12, 40) }, () => pick<string>(r, HEX) + pick<string>(r, HEX));
  const mode = r();
  let out: string[];
  if (mode < 0.34) out = pairs;
  else if (mode < 0.67) {
    out = [...pairs];
    for (let i = int(r, 1, 3); i > 0; i--) out.splice(int(r, 0, out.length), 0, pick<string>(r, [...WS, ...JUNK, ...HEX]));
  } else {
    out = [];
    for (let i = int(r, 10, 40); i > 0; i--) {
      const x = r();
      if (x < 0.8) out.push(pick<string>(r, HEX) + pick<string>(r, HEX));
      else if (x < 0.88) out.push(pick<string>(r, HEX));
      else if (x < 0.95) out.push(pick<string>(r, WS));
      else out.push(pick<string>(r, JUNK));
    }
  }
  return (r() < 0.3 ? pick<string>(r, ['0x', '0X']) : '') + out.join('');
}

const INPUTS: string[] = (() => {
  const r = rng(0xc17a7e);
  return Array.from({ length: N }, () => gen(r));
})();

const toBytes = (hex: string) => Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16));

function strictRef(s: string): Uint8Array | null {
  const m = /^(?:0[xX])?((?:[0-9a-fA-F]{2})*)$/.exec(s);
  return m ? toBytes(m[1]!) : null;
}

/** Python bytes.fromhex semantics: ASCII whitespace allowed between bytes. */
function pyFromhex(s: string): Uint8Array | null {
  const t = /^0[xX]/.test(s) ? s.slice(2) : s;
  const out: number[] = [];
  let i = 0;
  while (i < t.length) {
    if (' \t\n\r\x0b\x0c'.includes(t[i]!)) { i++; continue; }
    const pair = t.slice(i, i + 2);
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) return null;
    out.push(parseInt(pair, 16));
    i += 2;
  }
  return Uint8Array.from(out);
}

/** The pre-hardening JS decoder (reads floor(len/2) pairs; odd tail dropped), when every pair read is hex. */
function jsLegacy(s: string): Uint8Array | null {
  const t = s.replace(/^0x/, '');
  const body = t.slice(0, Math.floor(t.length / 2) * 2);
  return /^[0-9a-fA-F]*$/.test(body) ? toBytes(body) : null;
}

function guardRefuses(y: string): boolean {
  try {
    assertNoKeyShareMaterial({ x: 1, y });
    return false;
  } catch {
    return true;
  }
}

describe('guard vs parser differential', () => {
  it('hexToBytes agrees with the strict reference grammar', () => {
    const cm = new CryptoManager();
    const bad: string[] = [];
    for (const s of INPUTS) {
      let got: Uint8Array | null;
      try { got = cm.hexToBytes(s); } catch { got = null; }
      const ref = strictRef(s);
      if ((got === null) !== (ref === null) || (got && ref && Buffer.compare(Buffer.from(got), Buffer.from(ref)) !== 0)) bad.push(s);
    }
    expect(bad.slice(0, 3)).toEqual([]);
  });

  it.each([['strict', strictRef], ['fromhex', pyFromhex], ['js-legacy', jsLegacy]] as const)(
    'guard refuses everything the %s decoder accepts at share length',
    (_n, decode) => {
      let accepted = 0;
      const missed: string[] = [];
      for (const s of INPUTS) {
        const b = decode(s);
        if (b && b.length >= MIN) {
          accepted++;
          if (!guardRefuses(s)) missed.push(s);
        }
      }
      expect(accepted).toBeGreaterThan(1000);
      expect(missed.slice(0, 3)).toEqual([]);
    },
  );
});
