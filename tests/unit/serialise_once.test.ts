/**
 * Serialise once (deployModel).
 *
 * deployModel serialises txData exactly once, runs the share guard on
 * JSON.parse of those bytes, and sends those same bytes. Values that answer
 * differently on each read (a toJSON that changes after its first call, a
 * getter, a Proxy) can therefore not get past the guard.
 */
import { ethers } from 'ethers';
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

/** Deploy, then assert no calldata that went out carries share material. */
async function deployAndCheck(meta: Record<string, unknown>): Promise<void> {
  const { c, sent } = client();
  try {
    await c.deployModel(MODEL, cfg(meta));
  } catch (e) {
    expect(String(e)).toMatch(/key share|key-share/);
  }
  for (const data of sent) {
    expect(() => shareGuard.assertNoKeyShareMaterial(JSON.parse(ethers.toUtf8String(data)))).not.toThrow();
  }
}

describe('values that change between reads never get a share sent', () => {
  it('toJSON that is benign on the first call', async () => {
    await deployAndCheck({ m: { toJSON: flipAfter(1, { x: 1, y: '10' }, { x: 1, y: Y }) } });
  });
  it('toJSON on the metadata object itself', async () => {
    await deployAndCheck({ toJSON: flipAfter(1, { note: 'ok' }, { s: { x: 1, y: Y } }) } as unknown as Record<string, unknown>);
  });
  it.each([1, 2, 3])('an enumerable getter that changes after read %i', async (n) => {
    const share: Record<string, unknown> = { x: 1 };
    Object.defineProperty(share, 'y', { get: flipAfter(n, '10', Y), enumerable: true });
    await deployAndCheck({ share });
  });
  it.each([1, 2, 3])('a Proxy that changes after read %i', async (n) => {
    const next = flipAfter(n, '10', Y);
    const share = new Proxy({ x: 1, y: '10' } as Record<string, unknown>, {
      get: (t, k) => (k === 'y' ? next() : Reflect.get(t, k)),
    });
    await deployAndCheck({ share });
  });
});

describe('the guard sees exactly the bytes that are sent', () => {
  it('guard input equals JSON.parse of the sent calldata', async () => {
    const spy = jest.spyOn(shareGuard, 'assertNoKeyShareMaterial');
    const { c, sent } = client();
    // A Date serialises to a string: the guard must see the string that is
    // sent, not the live Date object.
    await c.deployModel(MODEL, cfg({ note: 'ok', when: new Date(0) }));
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]![0]).toEqual(JSON.parse(ethers.toUtf8String(sent[0]!)));
    spy.mockRestore();
  });
  it('benign metadata still deploys', async () => {
    const { c, sent } = client();
    await c.deployModel(MODEL, cfg({ x: 1, y: '10' }));
    expect(sent).toHaveLength(1);
  });
});
