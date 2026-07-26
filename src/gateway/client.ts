/**
 * Inference gateway client (DEVX-S2) — OpenAI-compatible over infer.citrate.ai.
 *
 * The gateway is OpenAI-compatible on the wire, so this is a thin, typed client: a `cgk_` bearer
 * key + the base URL from the federation artifact. It carries the key; it does NOT mint keys
 * (issuance is server-side, E-2) and does NOT do x402 (server-side). Fail-closed: no key → a
 * typed error, never a silent call to an open endpoint or a fabricated response.
 */
import { FEDERATION_CONTRACT } from '../generated/contract';

const GW = FEDERATION_CONTRACT.gateway;

export class GatewayError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = 'GatewayError';
  }
}

export type GatewayFetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}>;

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface ChatCompletionRequest {
  model: string;
  messages: ChatMessage[];
  max_tokens?: number;
  temperature?: number;
  /** Streaming is not yet wrapped; use the OpenAI client directly for SSE. */
  stream?: false;
  [k: string]: unknown;
}

export interface GatewayClientConfig {
  /** A `cgk_` gateway key (operator-minted until E-2 self-serve lands). */
  apiKey: string;
  /** Defaults to the artifact gateway base URL (https://infer.citrate.ai). */
  baseUrl?: string;
  fetch?: GatewayFetch;
}

export class GatewayClient {
  private readonly baseUrl: string;
  private readonly fetch: GatewayFetch;

  constructor(private readonly config: GatewayClientConfig) {
    if (!config.apiKey) throw new GatewayError(`gateway API key not configured (need a ${GW.keyPrefix} key)`);
    const f = config.fetch ?? (globalThis.fetch as unknown as GatewayFetch | undefined);
    if (!f) throw new GatewayError('no fetch implementation available; pass config.fetch');
    this.fetch = f;
    this.baseUrl = (config.baseUrl ?? GW.baseUrl).replace(/\/$/, '');
  }

  /** POST /v1/chat/completions — OpenAI-shaped request and response. */
  async chatCompletions(req: ChatCompletionRequest): Promise<unknown> {
    return this.call('POST', '/v1/chat/completions', JSON.stringify(req));
  }

  /** GET /v1/models — the models the gateway serves (marketplace mode). */
  async listModels(): Promise<unknown> {
    return this.call('GET', '/v1/models');
  }

  /** GET /v1/usage — per-key spend breakdown (marketplace mode). */
  async getUsage(): Promise<unknown> {
    return this.call('GET', '/v1/usage');
  }

  /** GET /health — open readiness probe. */
  async health(): Promise<unknown> {
    const res = await this.fetch(`${this.baseUrl}/health`, { method: 'GET' });
    if (!res.ok) throw this.error(res.status);
    return res.json();
  }

  /** OpenAI-compat alias: `client.chat.completions.create(req)`. */
  get chat(): { completions: { create: (req: ChatCompletionRequest) => Promise<unknown> } } {
    return { completions: { create: (req) => this.chatCompletions(req) } };
  }

  private async call(method: string, path: string, body?: string): Promise<unknown> {
    const headers: Record<string, string> = { authorization: `Bearer ${this.config.apiKey}` };
    if (body) headers['content-type'] = 'application/json';
    const res = await this.fetch(`${this.baseUrl}${path}`, { method, headers, ...(body ? { body } : {}) });
    if (!res.ok) throw this.error(res.status);
    return res.json();
  }

  private error(status: number): GatewayError {
    const msg =
      status === 401 ? 'unauthorized: unknown or revoked gateway key'
      : status === 402 ? 'insufficient balance: top up the gateway key'
      : status === 429 ? 'rate limited: retry after backoff'
      : status === 503 ? 'gateway upstream unavailable'
      : `gateway request failed: ${status}`;
    return new GatewayError(msg, status);
  }
}
