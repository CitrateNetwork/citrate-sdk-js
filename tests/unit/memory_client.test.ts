/** Memory client — typed REST + BYOM MCP over a citrate-memories gateway. */
import {
  MemoryClient,
  MemoryError,
  ByomMemoryClient,
  type MemoryFetch,
} from '../../src/memory/client';

const ORIGIN = 'https://mem-gateway.example.com';

function fetchReturning(status: number, body: unknown, text?: string): MemoryFetch {
  return () =>
    Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () => text ?? JSON.stringify(body),
    });
}

describe('MemoryClient (REST)', () => {
  it('is fail-closed without an origin', () => {
    // @ts-expect-error intentionally missing origin
    expect(() => new MemoryClient({})).toThrow(MemoryError);
  });

  it('health needs no token and hits /api/health', async () => {
    let seen = '';
    const fetch: MemoryFetch = (url) => {
      seen = url;
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({ ok: true, service: 'mem-gateway' }),
        text: async () => '{}',
      });
    };
    const client = new MemoryClient({ origin: ORIGIN, fetch });
    const h = await client.health();
    expect(seen).toBe(`${ORIGIN}/api/health`);
    expect(h.ok).toBe(true);
  });

  it('org routes fail closed without an id_token', async () => {
    const client = new MemoryClient({ origin: ORIGIN, fetch: fetchReturning(200, {}) });
    await expect(client.org('acme').recall({ repo: 'r' })).rejects.toThrow(/id_token required/);
  });

  it('recall builds the org/repo URL with budget + bearer', async () => {
    let seenUrl = '';
    const fetch: MemoryFetch = (url, init) => {
      seenUrl = url;
      expect(init?.headers?.['authorization']).toBe('Bearer id.jwt');
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({ repo: 'r', watermark: null, total_in_tenant: 3, count: 0, items: [] }),
        text: async () => '{}',
      });
    };
    const client = new MemoryClient({ origin: ORIGIN, idToken: 'id.jwt', fetch });
    const r = await client.org('citrate-federation').recall({ repo: 'citrate-chain', budget: 5 });
    expect(seenUrl).toBe(
      `${ORIGIN}/api/orgs/citrate-federation/recall?repo=citrate-chain&budget=5`,
    );
    expect(r.total_in_tenant).toBe(3);
  });

  it('search requires q and passes include_in_flight', async () => {
    let seenUrl = '';
    const fetch: MemoryFetch = (url) => {
      seenUrl = url;
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({ repo: 'r', watermark: null, total_in_tenant: 0, count: 0, items: [] }),
        text: async () => '{}',
      });
    };
    const org = new MemoryClient({ origin: ORIGIN, idToken: 't', fetch }).org('o');
    await expect(org.search({ repo: 'r', q: '' })).rejects.toThrow(/q required/);
    await org.search({ repo: 'r', q: 'consensus', includeInFlight: true });
    expect(seenUrl).toContain('q=consensus');
    expect(seenUrl).toContain('include_in_flight=true');
  });

  it('assert POSTs the body and returns the write receipt', async () => {
    let seenBody = '';
    const fetch: MemoryFetch = (_url, init) => {
      seenBody = init?.body ?? '';
      expect(init?.method).toBe('POST');
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({ id: 'ab12', repo: 'r', author: 'ed25:pub', embedded: true, warning: null }),
        text: async () => '{}',
      });
    };
    const org = new MemoryClient({ origin: ORIGIN, idToken: 't', fetch }).org('o');
    const res = await org.assert({ repo: 'r', content: 'the reroll is address-neutral', kind: 'finding' });
    expect(JSON.parse(seenBody)).toEqual({ repo: 'r', content: 'the reroll is address-neutral', kind: 'finding' });
    expect(res.embedded).toBe(true);
  });

  it('maps status codes to typed errors', async () => {
    for (const [status, re] of [
      [401, /unauthorized/],
      [403, /forbidden/],
      [404, /not found/],
      [429, /rate limited/],
      [503, /upstream/],
    ] as const) {
      const org = new MemoryClient({ origin: ORIGIN, idToken: 't', fetch: fetchReturning(status, {}) }).org('o');
      await expect(org.recall({ repo: 'r' })).rejects.toThrow(re);
    }
  });
});

describe('ByomMemoryClient (MCP-over-HTTP)', () => {
  it('is fail-closed without sub or connect token', () => {
    // @ts-expect-error missing sub + token
    expect(() => new ByomMemoryClient({ origin: ORIGIN })).toThrow(MemoryError);
  });

  it('callTool wraps memory.* in a JSON-RPC tools/call and returns result', async () => {
    let seenUrl = '';
    let seenBody = '';
    const fetch: MemoryFetch = (url, init) => {
      seenUrl = url;
      seenBody = init?.body ?? '';
      expect(init?.headers?.['authorization']).toBe('Bearer connect.tok');
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({}),
        text: async () => JSON.stringify({ jsonrpc: '2.0', id: 1, result: { items: [] } }),
      });
    };
    const byom = new ByomMemoryClient({ origin: ORIGIN, sub: 'user-123', connectToken: 'connect.tok', fetch });
    const result = (await byom.recall({ repo: 'citrate-chain' })) as { items: unknown[] };
    expect(seenUrl).toBe(`${ORIGIN}/mcp/u/user-123`);
    const sent = JSON.parse(seenBody);
    expect(sent.method).toBe('tools/call');
    expect(sent.params).toEqual({ name: 'memory.recall', arguments: { repo: 'citrate-chain' } });
    expect(result.items).toEqual([]);
  });

  it('surfaces a JSON-RPC error as a typed MemoryError', async () => {
    const fetch: MemoryFetch = () =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({}),
        text: async () => JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32001, message: 'grant rejected' } }),
      });
    const byom = new ByomMemoryClient({ origin: ORIGIN, sub: 's', connectToken: 't', fetch });
    await expect(byom.verify({ id: 'ab' })).rejects.toThrow(/grant rejected/);
  });
});
