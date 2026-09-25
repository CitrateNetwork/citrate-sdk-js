/**
 * Hardening round 3 (JS): the share guard's structural match needs an x in
 * 1..255 and a share-length y (>= 16 bytes), so ordinary coordinate-like
 * caller metadata is not refused. Share-shaped values are still refused.
 */
import { assertNoKeyShareMaterial } from '../../src/crypto/shareGuard';

const Y32 = 'ab'.repeat(32);

describe('share guard: no false positives on coordinate-like metadata', () => {
  it.each([
    [{ x: 1, y: '10' }],
    [{ point: { x: 1, y: 'ff' } }],
    [{ theme: { x: 0, y: 'abcdef' } }],
    [{ x: 0, y: Y32 }],
    [{ x: 256, y: Y32 }],
    [{ x: 1.5, y: Y32 }],
    [{ x: 'one', y: Y32 }],
    [{ x: 1, y: 'ab'.repeat(15) }],
    [{ x: 1, y: 'abc'.repeat(11) }],
    [{ x: 1, y: new Uint8Array(2) }],
    [{ grid: JSON.stringify({ x: 3, y: '1234' }) }],
    [{ x: '0', y: Y32 }],
    [{ x: '256', y: Y32 }],
    [{ x: '1a', y: Y32 }],
    [{ x: 'a1', y: Y32 }],
    [{ x: '', y: Y32 }],
    [{ x: 1, y: new Uint8Array(15) }],
    [{ x: 1, y: [Y32] }],
    [{ x: [5], y: Y32 }],
    [{ x: ' 12', y: Y32 }],
    [{ x: '12 ', y: Y32 }],
  ])('allows case %#', (meta) => {
    expect(() => assertNoKeyShareMaterial(meta)).not.toThrow();
  });

  it.each([
    [{ a: { x: 1, y: Y32 } }],
    [{ a: { x: '255', y: '0x' + Y32 } }],
    [{ a: { x: 7, y: 'ab'.repeat(16) } }],
    [{ a: { x: 2, y: new Uint8Array(32) } }],
    [{ a: { x: 2, y: '1'.repeat(64) } }],
    [{ blob: JSON.stringify([{ x: 2, y: Y32 }]) }],
    [{ a: { x: 255, y: Y32 } }],
    [{ a: { x: '1', y: Y32 } }],
    [{ a: { x: '255', y: Y32 } }],
    [{ a: { x: 1, y: new Uint8Array(16) } }],
  ])('refuses share-shaped case %#', (meta) => {
    expect(() => assertNoKeyShareMaterial(meta)).toThrow(/shaped like a key share/);
  });
});
