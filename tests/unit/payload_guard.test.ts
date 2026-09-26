/**
 * Deploy payload is guarded as sent.
 *
 * deployModel guards the transaction data, serialises it once, guards the
 * parsed payload (duplicate keys refused), and sends that exact payload.
 */
import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { CitrateClient } from '../../src/client/CitrateClient';
import * as shareGuard from '../../src/crypto/shareGuard';
import { AccessType, ModelConfig, ModelType } from '../../src/types/Model';

const OWNER = '0x' + '11'.repeat(32);
const Y = 'ab'.repeat(32);
const MODEL = new TextEncoder().encode('m');

function client(): { c: CitrateClient; sent: string[] } {
  const c = new CitrateClient({ rpcUrl: 'http://127.0.0.1:8545', privateKey: OWNER });
  const sent: string[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (c as any).wallet.sendTransaction = async (tx: { data: string }) => {
    sent.push(tx.data);
    return {
      hash: '0x' + 'ab'.repeat(32),
      wait: async () => ({ logs: [{ topics: [ethers.id('ModelDeployed(bytes32,address)')], data: '0x' + 'ab'.repeat(64) }], gasUsed: 1n }),
    };
  };
  return { c, sent };
}

const cfg = (metadata: Record<string, unknown>): ModelConfig => ({
  name: 'm', modelType: ModelType.ONNX, accessType: AccessType.PUBLIC, accessPrice: 0n, encrypted: false, metadata,
});

function flipAfter<T>(n: number, first: T, later: T): () => T {
  let reads = 0;
  return () => (++reads <= n ? first : later);
}

async function deployAndCheck(meta: Record<string, unknown>): Promise<void> {
  const { c, sent } = client();
  try {
    await c.deployModel(MODEL, cfg(meta));
  } catch (e) {
    expect(String(e)).toMatch(/key share|key-share|duplicate/);
  }
  for (const data of sent) {
    expect(() => shareGuard.assertPayloadHasNoKeyShareMaterial(ethers.toUtf8String(data))).not.toThrow();
  }
}

describe('payload guarded as sent', () => {
  it('case 1', async () => {
    await deployAndCheck({ m: { toJSON: flipAfter(1, { x: 1, y: '10' }, { x: 1, y: Y }) } });
  });
  it('case 2', async () => {
    await deployAndCheck({ toJSON: flipAfter(1, { note: 'ok' }, { s: { x: 1, y: Y } }) } as unknown as Record<string, unknown>);
  });
  it.each([1, 2, 3])('case 3.%i', async (n) => {
    const share: Record<string, unknown> = { x: 1 };
    Object.defineProperty(share, 'y', { get: flipAfter(n, '10', Y), enumerable: true });
    await deployAndCheck({ share });
  });
  it.each([1, 2, 3])('case 4.%i', async (n) => {
    const next = flipAfter(n, '10', Y);
    const share = new Proxy({ x: 1, y: '10' } as Record<string, unknown>, {
      get: (t, k) => (k === 'y' ? next() : Reflect.get(t, k)),
    });
    await deployAndCheck({ share });
  });
  it.each([
    ['Uint8Array y', { s: { x: 1, y: new Uint8Array(32).fill(171) } }],
    ['Buffer y', { s: { x: 1, y: Buffer.alloc(32, 171) } }],
    ['integer-list y', { s: { x: 1, y: Array(32).fill(171) } }],
    ['duplicate y in a JSON string', { blob: '{"x": 1, "y": "' + Y + '", "y": "10"}' }],
    ['duplicate x in a JSON string', { blob: '{"x": 1, "x": "junk", "y": "' + Y + '"}' }],
  ])('refuses %s before sending', async (_n, meta) => {
    const { c, sent } = client();
    await expect(c.deployModel(MODEL, cfg(meta as Record<string, unknown>))).rejects.toThrow(/key share|duplicate/);
    expect(sent).toEqual([]);
  });
});

describe('the guard sees exactly the bytes that are sent', () => {
  it('payload guard input equals the sent calldata', async () => {
    const spy = jest.spyOn(shareGuard, 'assertPayloadHasNoKeyShareMaterial');
    const { c, sent } = client();
    await c.deployModel(MODEL, cfg({ note: 'ok', when: new Date(0) }));
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]![0]).toBe(ethers.toUtf8String(sent[0]!));
    spy.mockRestore();
  });
  it('benign metadata still deploys', async () => {
    const { c, sent } = client();
    await c.deployModel(MODEL, cfg({ x: 1, y: '10' }));
    expect(sent).toHaveLength(1);
  });
});

describe('shared raw payload vectors', () => {
  const raw: Array<{ name: string; refuse: boolean; text: string }> = JSON.parse(
    fs.readFileSync(path.join(__dirname, '../fixtures/share_guard_vectors.json'), 'utf8'),
  ).raw_payloads;
  it.each(raw.map((v) => [v.name, v] as const))('%s', (_n, v) => {
    if (v.refuse) expect(() => shareGuard.assertPayloadHasNoKeyShareMaterial(v.text)).toThrow();
    else expect(() => shareGuard.assertPayloadHasNoKeyShareMaterial(v.text)).not.toThrow();
  });
});

describe('duplicate-key detection', () => {
  const { hasDuplicateJsonKeys } = shareGuard;
  it.each([
    ['{"a":1,"a":2}', true],
    ['{"a":{"b":1},"c":{"b":2}}', false],
    ['[{"a":1},{"a":2}]', false],
    ['{"a":[{"b":1,"b":2}]}', true],
    ['{"k\\"q":1,"k\\"q":2}', true],
    ['{"s":"{\\"a\\":1,\\"a\\":2}","t":"a"}', false],
    ['{"a":"x,\\"a\\":1","b":2}', false],
    ['{"\\u0061":1,"a":2}', true],
    ['{"a":"\\\\","a":1}', true],
    ['{"a":1,"b":{"a":2},"c":3}', false],
  ])('%s -> %s', (text, dup) => {
    expect(() => JSON.parse(text)).not.toThrow();
    expect(hasDuplicateJsonKeys(text)).toBe(dup);
  });
  it('agrees with a reference on generated documents', () => {
    let seed = 7;
    const r = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 4294967296);
    const keyPool = ['a', 'b', 'a"b', 'x\\y', 'ü', '{', ','];
    const gen = (d: number): [string, boolean] => {
      if (d > 3 || r() < 0.3) {
        const s = JSON.stringify(keyPool[Math.floor(r() * keyPool.length)] + ':' + Math.floor(r() * 9));
        return [r() < 0.5 ? s : String(Math.floor(r() * 100)), false];
      }
      if (r() < 0.3) {
        const items = Array.from({ length: Math.floor(r() * 3) }, () => gen(d + 1));
        return ['[' + items.map((x) => x[0]).join(',') + ']', items.some((x) => x[1])];
      }
      const n = Math.floor(r() * 4);
      const keys = Array.from({ length: n }, () => keyPool[Math.floor(r() * keyPool.length)]!);
      const vals = keys.map(() => gen(d + 1));
      const dup = new Set(keys).size !== keys.length || vals.some((v) => v[1]);
      return ['{' + keys.map((k, i) => JSON.stringify(k) + ':' + vals[i]![0]).join(',') + '}', dup];
    };
    for (let i = 0; i < 3000; i++) {
      const [text, dup] = gen(0);
      expect(hasDuplicateJsonKeys(text)).toBe(dup);
    }
  });
});
