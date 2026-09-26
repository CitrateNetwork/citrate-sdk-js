/**
 * Hardening round 4 (JS).
 *
 * 1. The share parser (CryptoManager.hexToBytes, used by
 *    reconstructKeyFromShares) is strict: optional 0x/0X, even-length hex,
 *    nothing else.
 * 2. The guard refuses every y the parser accepts at share length (property
 *    test), so the two cannot drift.
 * 3. The guard checks what is actually serialised (objects with toJSON).
 * 4. Both SDKs run the same vectors: tests/fixtures/share_guard_vectors.json,
 *    byte-identical in citrate-sdk-python (sha256 pinned below).
 */
import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'fs';
import * as path from 'path';
import { CryptoManager } from '../../src/crypto/CryptoManager';
import { KeyManager } from '../../src/crypto/KeyManager';
import { assertNoKeyShareMaterial } from '../../src/crypto/shareGuard';

const VECTORS = path.join(__dirname, '../fixtures/share_guard_vectors.json');
const VECTORS_SHA256 = '8f336f469be58046e7984bf61756d513df9ba497aca8feb9fc8641e2c6a4b805';
const Y = 'ab'.repeat(32);

describe('shared vectors', () => {
  it('the vector file is the shared copy', () => {
    expect(createHash('sha256').update(fs.readFileSync(VECTORS)).digest('hex')).toBe(VECTORS_SHA256);
  });
  const vecs: Array<{ name: string; refuse: boolean; meta: unknown }> = JSON.parse(fs.readFileSync(VECTORS, 'utf8')).vectors;
  it.each(vecs.map((v) => [v.name, v] as const))('%s', (_name, v) => {
    if (v.refuse) expect(() => assertNoKeyShareMaterial(v.meta)).toThrow();
    else expect(() => assertNoKeyShareMaterial(v.meta)).not.toThrow();
  });
});

describe('strict share parser', () => {
  const cm = new CryptoManager();
  it.each([Y + 'z', Y + '\n', Y + ' ', ' ' + Y, 'ab cd' + 'ab'.repeat(30), Y + 'a', 'xyz', '0x0'])('rejects %j', (y) => {
    expect(() => cm.hexToBytes(y)).toThrow(/hex/);
    expect(() => new KeyManager('0x' + '11'.repeat(32)).reconstructKeyFromShares([{ x: '1', y }], 1)).toThrow();
  });
  it.each([Y, Y.toUpperCase(), '0x' + Y, '0X' + Y, '', '0x'])('accepts %j', (y) => {
    expect(cm.hexToBytes(y).length).toBe(y.replace(/^0[xX]/, '').length / 2);
  });
  it('the guard refuses every y the parser accepts at share length', () => {
    for (const n of [16, 17, 32, 64]) {
      for (let i = 0; i < 25; i++) {
        const hex = randomBytes(n).toString('hex');
        for (const y of [hex, hex.toUpperCase(), '0x' + hex, '0X' + hex]) {
          expect(cm.hexToBytes(y).length).toBe(n);
          expect(() => assertNoKeyShareMaterial({ x: 1 + (n % 200), y })).toThrow();
        }
      }
    }
  });
});

describe('guard checks the serialised form', () => {
  it('refuses an object whose toJSON emits a share', () => {
    const sneaky = { toJSON: () => ({ x: 1, y: Y }) };
    expect(() => assertNoKeyShareMaterial({ meta: sneaky })).toThrow(/shaped like a key share/);
  });
  it('refuses a toJSON that emits a deny-listed field', () => {
    const sneaky = { toJSON: () => ({ keyShares: [] }) };
    expect(() => assertNoKeyShareMaterial({ meta: sneaky })).toThrow(/key-share material/);
  });
  it('accepts a benign toJSON', () => {
    expect(() => assertNoKeyShareMaterial({ when: new Date(0), meta: { toJSON: () => ({ x: 1, y: '10' }) } })).not.toThrow();
  });
});

describe('round-4 edges', () => {
  it('a value JSON.stringify cannot serialise is still scanned directly', () => {
    expect(() => assertNoKeyShareMaterial({ n: BigInt(1), a: { x: 1, y: Y } })).toThrow(/shaped like a key share/);
    expect(() => assertNoKeyShareMaterial({ n: BigInt(1), a: { x: 1, y: '10' } })).not.toThrow();
  });
  it('hexToBytes refuses a non-string even if it stringifies to hex', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => new CryptoManager().hexToBytes(1234 as any)).toThrow(/hex/);
  });
});
