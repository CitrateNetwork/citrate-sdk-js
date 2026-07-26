/** DEVX-S2 / F4 — OpenAI-compatible gateway client. */
import { GatewayClient, GatewayError, type GatewayFetch } from '../../src/gateway/client';
import { FEDERATION_CONTRACT } from '../../src/generated/contract';

const BASE = FEDERATION_CONTRACT.gateway.baseUrl;

function fetchReturning(status: number, body: unknown): GatewayFetch {
  return () => Promise.resolve({ ok: status >= 200 && status < 300, status, json: async () => body, text: async () => JSON.stringify(body) });
}

describe('GatewayClient', () => {
  it('is fail-closed without an API key', () => {
    // @ts-expect-error intentionally missing apiKey
    expect(() => new GatewayClient({})).toThrow(GatewayError);
  });

  it('posts an OpenAI-shaped chat completion to the artifact base URL', async () => {
    let seenUrl = '';
    const fetch: GatewayFetch = (url, init) => {
      seenUrl = url;
      expect(init?.headers?.['authorization']).toBe('Bearer cgk_test');
      return Promise.resolve({ ok: true, status: 200, json: async () => ({ id: 'cmpl-1' }), text: async () => '{}' });
    };
    const client = new GatewayClient({ apiKey: 'cgk_test', fetch });
    const res = (await client.chat.completions.create({ model: 'gemma', messages: [{ role: 'user', content: 'hi' }] })) as { id: string };
    expect(seenUrl).toBe(`${BASE}/v1/chat/completions`);
    expect(res.id).toBe('cmpl-1');
  });

  it('maps status codes to typed errors', async () => {
    for (const [status, re] of [[401, /unauthorized/], [402, /balance/], [429, /rate limited/], [503, /unavailable/]] as const) {
      const client = new GatewayClient({ apiKey: 'cgk_x', fetch: fetchReturning(status, {}) });
      await expect(client.listModels()).rejects.toThrow(re);
    }
  });
});
