/**
 * Genesis guard applies per endpoint.
 *
 * With several RPC URLs the client uses an ethers FallbackProvider. A read such as block 0 is
 * answered by a quorum of endpoints, but a signed transaction is broadcast to every endpoint.
 * So each endpoint that can receive a send (or an eth_call against a book address) must report
 * the expected block 0 itself; a quorum is not enough.
 *
 * The endpoints here are local loopback JSON-RPC servers on ephemeral ports (no real node).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { FallbackProvider, JsonRpcProvider, Wallet, type Provider } from 'ethers';
import { CitrateClient } from '../../src/client/CitrateClient';
import { ComputeRefunds } from '../../src/compute/refunds';
import { verifyWalletAddressOnChain } from '../../src/identity/wallet';
import { WrongNetworkError, assertGenesis, type GenesisSource } from '../../src/utils/network';

const R1006_GENESIS = '0xa3651a272fe411948cbb4cf7cca4cee44be4248d32ab4376cea7636821c6cdd4';
const R1005_GENESIS = '0x1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1';
const OWNER = '0x' + '11'.repeat(32);
const UID = '0x' + '42'.repeat(32);
const ZERO32 = '0x' + '00'.repeat(32);

type Mode = 'ok' | 'error' | 'hang';

/** A loopback JSON-RPC endpoint on chain 40204 whose block 0 is `genesis`. */
class FakeNode {
  readonly methods: string[] = [];
  genesis: string;
  block0: Mode = 'ok';
  private server!: Server;
  private hung: ServerResponse[] = [];
  url = '';

  constructor(genesis: string) {
    this.genesis = genesis;
  }

  /** How many times `method` was called (with `firstParam` as its first parameter, if given). */
  count(method: string, firstParam?: string): number {
    return this.methods.filter((m) =>
      firstParam === undefined ? m === method || m.startsWith(`${method}:`) : m === `${method}:${firstParam}`,
    ).length;
  }

  private block(number: number, hash: string) {
    return {
      number: '0x' + number.toString(16),
      hash,
      parentHash: ZERO32,
      timestamp: '0x0',
      nonce: '0x0000000000000000',
      difficulty: '0x0',
      gasLimit: '0x1c9c380',
      gasUsed: '0x0',
      miner: '0x' + '00'.repeat(20),
      extraData: '0x',
      baseFeePerGas: '0x1',
      transactions: [],
    };
  }

  private answer(req: { id: number; method: string; params?: unknown[] }): unknown {
    const p0 = Array.isArray(req.params) ? String(req.params[0]) : '';
    this.methods.push(req.method === 'eth_getBlockByNumber' ? `${req.method}:${p0}` : req.method);
    const ok = (result: unknown) => ({ jsonrpc: '2.0', id: req.id, result });
    switch (req.method) {
      case 'eth_chainId':
        return ok('0x9d0c');
      case 'net_version':
        return ok('40204');
      case 'eth_blockNumber':
        return ok('0x10');
      case 'eth_getBlockByNumber':
        if (p0 === '0x0') {
          if (this.block0 === 'error') {
            return { jsonrpc: '2.0', id: req.id, error: { code: -32000, message: 'block 0 unavailable' } };
          }
          return ok(this.block(0, this.genesis));
        }
        return ok(this.block(16, '0x' + '0f'.repeat(32)));
      case 'eth_gasPrice':
      case 'eth_maxPriorityFeePerGas':
        return ok('0x1');
      case 'eth_getTransactionCount':
        return ok('0x0');
      case 'eth_estimateGas':
        return ok('0x5208');
      case 'eth_getCode':
        return ok('0x6080');
      case 'eth_call':
        return ok('0x' + '00'.repeat(31) + '05');
      case 'eth_sendRawTransaction':
        // Recorded above; refuse so the caller stops instead of waiting for a receipt.
        return { jsonrpc: '2.0', id: req.id, error: { code: -32000, message: 'test endpoint: not mined' } };
      default:
        return { jsonrpc: '2.0', id: req.id, error: { code: -32601, message: `unsupported ${req.method}` } };
    }
  }

  async start(): Promise<void> {
    this.server = createServer((req: IncomingMessage, res: ServerResponse) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const parsed = JSON.parse(body);
        const reqs = Array.isArray(parsed) ? parsed : [parsed];
        const hang = this.block0 === 'hang' && reqs.some(
          (r: { method: string; params?: unknown[] }) =>
            r.method === 'eth_getBlockByNumber' && Array.isArray(r.params) && r.params[0] === '0x0',
        );
        if (hang) {
          for (const r of reqs) this.methods.push(`${r.method}:${Array.isArray(r.params) ? String(r.params[0]) : ''}`);
          this.hung.push(res);
          return;
        }
        const out = reqs.map((r: { id: number; method: string; params?: unknown[] }) => this.answer(r));
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify(Array.isArray(parsed) ? out : out[0]));
      });
    });
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }

  async stop(): Promise<void> {
    for (const r of this.hung) r.destroy();
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }
}

/** ethers providers reuse an identical request's result for 250 ms; wait past that. */
const pastProviderCache = () => new Promise((resolve) => setTimeout(resolve, 300));

const DEPLOY = {
  name: 'm',
  modelType: 'onnx',
  accessType: 'public',
  accessPrice: 0n,
  encrypted: false,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
} as any;

let nodes: FakeNode[] = [];
const providers: Provider[] = [];

async function startNodes(...genesis: string[]): Promise<FakeNode[]> {
  nodes = genesis.map((g) => new FakeNode(g));
  await Promise.all(nodes.map((n) => n.start()));
  return nodes;
}

function track<T extends Provider>(p: T): T {
  providers.push(p);
  return p;
}

function client(cfg: Record<string, unknown> = {}): CitrateClient {
  const c = new CitrateClient({ rpcUrl: nodes.map((n) => n.url), privateKey: OWNER, ...cfg });
  track((c as unknown as { provider: Provider }).provider);
  return c;
}

function fallback(): FallbackProvider {
  return track(
    new FallbackProvider(
      nodes.map((n, i) => ({ provider: track(new JsonRpcProvider(n.url)), priority: i + 1, weight: 1 })),
    ),
  );
}

afterEach(async () => {
  for (const p of providers.splice(0)) (p as unknown as { destroy(): void }).destroy();
  await Promise.all(nodes.map((n) => n.stop()));
  nodes = [];
});

describe('CitrateClient with several RPC URLs checks every endpoint', () => {
  it('refuses when one of three endpoints is on another genesis, though a quorum agrees', async () => {
    await startNodes(R1006_GENESIS, R1006_GENESIS, R1005_GENESIS);
    const err = await client().verifyNetwork().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WrongNetworkError);
    expect((err as Error).message).toContain(R1005_GENESIS);
  });

  it('the wrong-genesis endpoint never receives the signed transaction', async () => {
    const [, , wrong] = await startNodes(R1006_GENESIS, R1006_GENESIS, R1005_GENESIS);
    await expect(client().deployModel(new TextEncoder().encode('m'), DEPLOY)).rejects.toThrow(WrongNetworkError);
    expect(wrong!.count('eth_sendRawTransaction')).toBe(0);
    for (const n of nodes) expect(n.count('eth_sendRawTransaction')).toBe(0);
  });

  it('inference on a mixed set refuses before anything is broadcast', async () => {
    await startNodes(R1005_GENESIS, R1006_GENESIS, R1006_GENESIS);
    await expect(
      client().inference({ modelId: '0x' + 'ab'.repeat(32), inputData: { x: 1 } }),
    ).rejects.toThrow(WrongNetworkError);
    for (const n of nodes) expect(n.count('eth_sendRawTransaction')).toBe(0);
  });

  it('a failed endpoint is not cached as verified: the next call re-reads it', async () => {
    const [, , wrong] = await startNodes(R1006_GENESIS, R1006_GENESIS, R1005_GENESIS);
    const c = client();
    await expect(c.verifyNetwork()).rejects.toThrow(WrongNetworkError);
    await pastProviderCache();
    await expect(c.verifyNetwork()).rejects.toThrow(WrongNetworkError);
    expect(wrong!.count('eth_getBlockByNumber', '0x0')).toBeGreaterThanOrEqual(2);
    // The operator fixes the endpoint: the next check passes because it reads block 0 again.
    wrong!.genesis = R1006_GENESIS;
    await pastProviderCache();
    await expect(c.verifyNetwork()).resolves.toBeUndefined();
  });

  it('refuses when one endpoint cannot return block 0', async () => {
    const [, broken] = await startNodes(R1006_GENESIS, R1006_GENESIS, R1006_GENESIS);
    broken!.block0 = 'error';
    await expect(client().verifyNetwork()).rejects.toThrow(WrongNetworkError);
  });

  it('refuses, within the client timeout, when one endpoint never answers block 0', async () => {
    const [, , silent] = await startNodes(R1006_GENESIS, R1006_GENESIS, R1006_GENESIS);
    silent!.block0 = 'hang';
    const started = Date.now();
    await expect(client({ timeout: 300 }).verifyNetwork()).rejects.toThrow(WrongNetworkError);
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it('a fully r1006 set passes, reads block 0 from each endpoint, and broadcasts to all', async () => {
    await startNodes(R1006_GENESIS, R1006_GENESIS, R1006_GENESIS);
    const c = client();
    await expect(c.verifyNetwork()).resolves.toBeUndefined();
    for (const n of nodes) expect(n.count('eth_getBlockByNumber', '0x0')).toBeGreaterThanOrEqual(1);
    // The send reaches the endpoints (they refuse to mine it, so the call rejects, but not
    // with WrongNetworkError).
    const err = await c.deployModel(new TextEncoder().encode('m'), DEPLOY).catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(WrongNetworkError);
    expect(nodes.some((n) => n.count('eth_sendRawTransaction') > 0)).toBe(true);
  });
});

describe('caller-supplied FallbackProvider: every endpoint is checked', () => {
  it('ComputeRefunds refuses before any eth_call when one endpoint is on another genesis', async () => {
    await startNodes(R1006_GENESIS, R1006_GENESIS, R1005_GENESIS);
    const r = new ComputeRefunds(fallback());
    await expect(r.refundOwed('0x' + 'ab'.repeat(20))).rejects.toThrow(WrongNetworkError);
    for (const n of nodes) expect(n.count('eth_call')).toBe(0);
  });

  it('verifyWalletAddressOnChain refuses when one endpoint is on another genesis', async () => {
    await startNodes(R1005_GENESIS, R1006_GENESIS, R1006_GENESIS);
    await expect(verifyWalletAddressOnChain(UID, fallback())).rejects.toThrow(WrongNetworkError);
    for (const n of nodes) expect(n.count('eth_call')).toBe(0);
  });
});

describe('nested FallbackProviders: every leaf endpoint is checked', () => {
  /** outer FallbackProvider -> inner FallbackProvider -> the loopback endpoints. */
  function nested(): FallbackProvider {
    return track(new FallbackProvider([{ provider: fallback(), priority: 1, weight: 1 }]));
  }

  it('a claim through an outer FallbackProvider wrapping an inner one refuses; r1005 never gets the raw tx', async () => {
    const [, , wrong] = await startNodes(R1006_GENESIS, R1006_GENESIS, R1005_GENESIS);
    const signer = new Wallet(OWNER, nested());
    const r = new ComputeRefunds(signer);
    await expect(r.claimNativeRefund()).rejects.toThrow(WrongNetworkError);
    expect(wrong!.count('eth_sendRawTransaction')).toBe(0);
    for (const n of nodes) expect(n.count('eth_sendRawTransaction')).toBe(0);
    for (const n of nodes) expect(n.count('eth_call')).toBe(0);
  });

  it('verifyWalletAddressOnChain refuses through a nested FallbackProvider', async () => {
    await startNodes(R1006_GENESIS, R1005_GENESIS, R1006_GENESIS);
    await expect(verifyWalletAddressOnChain(UID, nested())).rejects.toThrow(WrongNetworkError);
    for (const n of nodes) expect(n.count('eth_call')).toBe(0);
  });

  it('a nested all-r1006 set passes: every leaf reads block 0 and the claim is broadcast', async () => {
    await startNodes(R1006_GENESIS, R1006_GENESIS, R1006_GENESIS);
    const r = new ComputeRefunds(new Wallet(OWNER, nested()));
    const err = await r.claimNativeRefund().catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(WrongNetworkError);
    for (const n of nodes) expect(n.count('eth_getBlockByNumber', '0x0')).toBeGreaterThanOrEqual(1);
    expect(nodes.some((n) => n.count('eth_sendRawTransaction') > 0)).toBe(true);
  });
});

describe('provider shapes that cannot be resolved to endpoints fail closed', () => {
  /** A provider-like object that answers block 0 with r1006 and wraps `inner`. */
  function wrapper(inner: unknown[] | unknown): GenesisSource & { providerConfigs: unknown } {
    return {
      getBlock: async () => ({ hash: R1006_GENESIS }),
      providerConfigs: inner,
    };
  }

  it('a providerConfigs cycle refuses', async () => {
    const a = wrapper([]);
    (a as { providerConfigs: unknown }).providerConfigs = [{ provider: a }];
    await expect(assertGenesis(a, R1006_GENESIS)).rejects.toThrow(WrongNetworkError);
    await expect(assertGenesis(a, R1006_GENESIS)).rejects.toThrow(/contains itself|cannot resolve/);
  });

  it('nesting deeper than the bound refuses', async () => {
    let p: GenesisSource = { getBlock: async () => ({ hash: R1006_GENESIS }) };
    for (let i = 0; i < 12; i++) p = wrapper([{ provider: p }]);
    await expect(assertGenesis(p, R1006_GENESIS)).rejects.toThrow(WrongNetworkError);
    await expect(assertGenesis(p, R1006_GENESIS)).rejects.toThrow(/nested more than/);
  });

  it('a providerConfigs that is not a list refuses', async () => {
    await expect(assertGenesis(wrapper({ provider: 'x' }), R1006_GENESIS)).rejects.toThrow(WrongNetworkError);
  });

  it('an empty providerConfigs at any level refuses', async () => {
    const leaf: GenesisSource = { getBlock: async () => ({ hash: R1006_GENESIS }) };
    await expect(
      assertGenesis(wrapper([{ provider: leaf }, { provider: wrapper([]) }]), R1006_GENESIS),
    ).rejects.toThrow(WrongNetworkError);
  });

  it('a deep cycle (a -> b -> a) refuses as a cycle', async () => {
    const a = wrapper([]);
    const b = wrapper([{ provider: a }]);
    (a as { providerConfigs: unknown }).providerConfigs = [{ provider: b }];
    await expect(assertGenesis(a, R1006_GENESIS)).rejects.toThrow(/contains itself/);
  });

  it('two levels of r1006 leaves pass', async () => {
    const leaf: GenesisSource = { getBlock: async () => ({ hash: R1006_GENESIS }) };
    await expect(
      assertGenesis(wrapper([{ provider: leaf }, { provider: wrapper([{ provider: leaf }]) }]), R1006_GENESIS),
    ).resolves.toBeUndefined();
  });
});
