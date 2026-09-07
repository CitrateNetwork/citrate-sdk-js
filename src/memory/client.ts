/**
 * Memory client — typed access to a citrate-memories gateway ("git for agents").
 *
 * Two auth surfaces, mirroring the gateway:
 *   1. `MemoryClient` — OIDC id_token bearer over the per-org REST routes
 *      (`/api/orgs/:org/{layout,recall,search,neighbors,verify,review,assert}`).
 *   2. `ByomMemoryClient` — a connect-token + `sub` bearer over the BYOM
 *      MCP-over-HTTP endpoint (`POST /mcp/u/:sub`), speaking JSON-RPC to the same
 *      11 `memory.*` tools the stdio/daemon transports serve.
 *
 * Thin and typed: it carries a token and shapes requests/responses. It mints no
 * tokens (issuance is server-side) and holds no keys. Fail-closed — a missing
 * origin, token, or fetch throws a typed `MemoryError`, never a silent call.
 *
 * The gateway origin is per-deployment (e.g. `MEM_GATEWAY_ORIGIN`), so it is a
 * required config field — no hostname is baked in.
 */

import { enforceTransportSecurity } from '../utils/transport';

export class MemoryError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'MemoryError';
  }
}

export type MemoryFetch = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}>;

// --- Response shapes (as the gateway serializes them; strings are Rust Debug
// discriminants, e.g. plane "Derived"/"Asserted", status "Active"/"Superseded"). ---

export interface RecallItem {
  id: string;
  kind: string;
  repo: string;
  title: string;
  valid_from: number;
  plane: string;
  trust_tier: string;
  status: string;
  /** Similarity score on search results; null on plain storyline recall. */
  score: number | null;
  /** null for canonical (merged) items; the branch name for in-flight items. */
  in_flight_branch: string | null;
}

export interface RecallResult {
  repo: string;
  watermark: string | null;
  total_in_tenant: number;
  count: number;
  items: RecallItem[];
}

export interface Neighbor {
  edge_kind: string;
  direction: string;
  quarantined: boolean;
  node: RecallItem | null;
}

export interface NeighborsResult {
  id: string;
  count: number;
  neighbors: Neighbor[];
}

export interface VerifyResult {
  id: string;
  verdict: 'current' | 'superseded' | 'contradicted' | string;
  superseded: boolean;
  contradicted: boolean;
  node: RecallItem;
  neighbors: Neighbor[];
}

export interface ReviewResult {
  repo: string;
  total_in_tenant: number;
  count: number;
  items: RecallItem[];
}

export interface AssertInput {
  repo: string;
  content: string;
  /** Node kind, e.g. "rationale" (default), "finding", "doc". */
  kind?: string;
  /** Real-world date this became true (ms since epoch). Defaults to now server-side. */
  valid_from?: number;
}

export interface AssertResult {
  id: string;
  repo: string;
  author: string;
  embedded: boolean;
  warning: string | null;
}

export interface SceneNode {
  id: string;
  x: number;
  y: number;
  kind: string;
  repo: string;
  title: string;
  status: string;
}

export interface SceneEdge {
  from: string;
  to: string;
  kind: string;
}

export interface Scene {
  node_count: number;
  nodes: SceneNode[];
  edges: SceneEdge[];
}

export interface HealthResult {
  ok: boolean;
  service: string;
}

export interface MemoryClientConfig {
  /** Gateway origin, e.g. `https://mem-gateway.example.com` (MEM_GATEWAY_ORIGIN). */
  origin: string;
  /** OIDC id_token bearer, required for every `/api/orgs/*` route (not `health`). */
  idToken?: string;
  fetch?: MemoryFetch;
  /** Opt in to a remote plaintext origin (SJS-B / SPY-B-009). The id_token is a
   *  bearer credential; a remote `http://` origin is refused by default. */
  allowInsecureHttp?: boolean;
}

function resolveFetch(f?: MemoryFetch): MemoryFetch {
  const chosen = f ?? (globalThis.fetch as unknown as MemoryFetch | undefined);
  if (!chosen) throw new MemoryError('no fetch implementation available; pass config.fetch');
  return chosen;
}

function statusError(status: number, context: string): MemoryError {
  const msg =
    status === 401
      ? 'unauthorized: missing, expired, or invalid id_token'
      : status === 403
        ? 'forbidden: no membership or capability for this org/resource'
        : status === 404
          ? 'not found: unknown org, route, or node id prefix'
          : status === 429
            ? 'rate limited: retry after backoff'
            : status >= 500
              ? `gateway upstream error (${status})`
              : `request failed (${status})`;
  return new MemoryError(`${context}: ${msg}`, status);
}

/**
 * REST client over one citrate-memories gateway. Call `.org(id)` for the
 * per-org, per-repo read/write surface; `.health()` needs no token.
 */
export class MemoryClient {
  private readonly origin: string;
  private readonly fetch: MemoryFetch;

  constructor(private readonly config: MemoryClientConfig) {
    if (!config.origin) throw new MemoryError('memory gateway origin not configured');
    this.origin = enforceTransportSecurity(config.origin.replace(/\/$/, ''), {
      allowInsecureHttp: config.allowInsecureHttp ?? false,
    });
    this.fetch = resolveFetch(config.fetch);
  }

  /** GET /api/health — open readiness probe (no auth). */
  async health(): Promise<HealthResult> {
    const res = await this.fetch(`${this.origin}/api/health`, { method: 'GET' });
    if (!res.ok) throw statusError(res.status, 'health');
    return (await res.json()) as HealthResult;
  }

  /** Scope to an org for the read/write surface. */
  org(org: string): OrgMemory {
    if (!org) throw new MemoryError('org id required');
    return new OrgMemory(this.origin, org, this.fetch, () => this.requireToken());
  }

  private requireToken(): string {
    if (!this.config.idToken) {
      throw new MemoryError('id_token required for org routes; set config.idToken', 401);
    }
    return this.config.idToken;
  }
}

/** Per-org, per-repo read/write surface. Obtain via `MemoryClient.org(id)`. */
export class OrgMemory {
  constructor(
    private readonly origin: string,
    private readonly org: string,
    private readonly fetch: MemoryFetch,
    private readonly token: () => string,
  ) {}

  /** GET /api/orgs/:org/layout — the PCA-2D constellation scene for the org. */
  async layout(): Promise<Scene> {
    return this.get('layout', {}) as Promise<Scene>;
  }

  /** GET /api/orgs/:org/recall — the storyline of a repo (budgeted). */
  async recall(args: {
    repo: string;
    budget?: number;
    includeInFlight?: boolean;
  }): Promise<RecallResult> {
    this.needRepo(args.repo);
    return this.get('recall', {
      repo: args.repo,
      ...this.budget(args.budget),
      ...this.inFlight(args.includeInFlight),
    }) as Promise<RecallResult>;
  }

  /** GET /api/orgs/:org/search — semantic search within a repo. */
  async search(args: {
    repo: string;
    q: string;
    budget?: number;
    includeInFlight?: boolean;
  }): Promise<RecallResult> {
    this.needRepo(args.repo);
    if (!args.q) throw new MemoryError('search: q required');
    return this.get('search', {
      repo: args.repo,
      q: args.q,
      ...this.budget(args.budget),
      ...this.inFlight(args.includeInFlight),
    }) as Promise<RecallResult>;
  }

  /** GET /api/orgs/:org/neighbors — graph neighbors of a node (id prefix ok). */
  async neighbors(args: { repo: string; id: string; budget?: number }): Promise<NeighborsResult> {
    this.needRepo(args.repo);
    if (!args.id) throw new MemoryError('neighbors: id required');
    return this.get('neighbors', {
      repo: args.repo,
      id: args.id,
      ...this.budget(args.budget),
    }) as Promise<NeighborsResult>;
  }

  /** GET /api/orgs/:org/verify — is a node current, superseded, or contradicted? */
  async verify(args: { repo: string; id: string }): Promise<VerifyResult> {
    this.needRepo(args.repo);
    if (!args.id) throw new MemoryError('verify: id required');
    return this.get('verify', { repo: args.repo, id: args.id }) as Promise<VerifyResult>;
  }

  /** GET /api/orgs/:org/review — items a human should review (advisory/inactive). */
  async review(args: { repo: string; budget?: number }): Promise<ReviewResult> {
    this.needRepo(args.repo);
    return this.get('review', {
      repo: args.repo,
      ...this.budget(args.budget),
    }) as Promise<ReviewResult>;
  }

  /** POST /api/orgs/:org/assert — write a signed, append-only assertion. */
  async assert(input: AssertInput): Promise<AssertResult> {
    this.needRepo(input.repo);
    if (!input.content) throw new MemoryError('assert: content required');
    const body: Record<string, unknown> = { repo: input.repo, content: input.content };
    if (input.kind !== undefined) body.kind = input.kind;
    if (input.valid_from !== undefined) body.valid_from = input.valid_from;
    const res = await this.fetch(`${this.base()}/assert`, {
      method: 'POST',
      headers: { authorization: `Bearer ${this.token()}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw statusError(res.status, 'assert');
    return (await res.json()) as AssertResult;
  }

  private base(): string {
    return `${this.origin}/api/orgs/${encodeURIComponent(this.org)}`;
  }

  private async get(path: string, params: Record<string, string>): Promise<unknown> {
    const qs = new URLSearchParams(params).toString();
    const url = `${this.base()}/${path}${qs ? `?${qs}` : ''}`;
    const res = await this.fetch(url, {
      method: 'GET',
      headers: { authorization: `Bearer ${this.token()}` },
    });
    if (!res.ok) throw statusError(res.status, path);
    return res.json();
  }

  private needRepo(repo: string): void {
    if (!repo) throw new MemoryError('repo required');
  }

  private budget(n?: number): Record<string, string> {
    return n !== undefined ? { budget: String(n) } : {};
  }

  private inFlight(b?: boolean): Record<string, string> {
    return b ? { include_in_flight: 'true' } : {};
  }
}

// --------------------------------------------------------------------------
// BYOM — MCP-over-HTTP (connect token + sub), the 11 memory.* tools.
// --------------------------------------------------------------------------

/** The canonical memory tool names served over MCP. */
export type MemoryTool =
  | 'memory.recall'
  | 'memory.search'
  | 'memory.neighbors'
  | 'memory.as_of'
  | 'memory.verify'
  | 'memory.critique'
  | 'memory.analogy'
  | 'memory.assert'
  | 'memory.merge_diff'
  | 'memory.propose_edge'
  | 'memory.confirm_edge';

export interface ByomConfig {
  /** Gateway origin, e.g. `https://mem-gateway.example.com`. */
  origin: string;
  /** The connect-token-verified principal; must match the token's subject. */
  sub: string;
  /** HS256 connect token (byte-matches the gateway's MEM_CONNECT_SECRET issuance). */
  connectToken: string;
  fetch?: MemoryFetch;
  /** Opt in to a remote plaintext origin (SJS-B / SPY-B-009); refused by default. */
  allowInsecureHttp?: boolean;
}

/**
 * BYOM client: JSON-RPC to `POST /mcp/u/:sub`. The gateway mints the capability
 * grant server-side from the connect token, so the caller supplies no grant —
 * just the tool name and arguments. Agent adapters (e.g. citrate-agent-runtime)
 * wrap `callTool` for recall/assert hooks.
 */
export class ByomMemoryClient {
  private readonly url: string;
  private readonly fetch: MemoryFetch;
  private id = 0;

  constructor(private readonly config: ByomConfig) {
    if (!config.origin) throw new MemoryError('memory gateway origin not configured');
    if (!config.sub) throw new MemoryError('BYOM sub required');
    if (!config.connectToken) throw new MemoryError('BYOM connect token required');
    const origin = enforceTransportSecurity(config.origin.replace(/\/$/, ''), {
      allowInsecureHttp: config.allowInsecureHttp ?? false,
    });
    this.url = `${origin}/mcp/u/${encodeURIComponent(config.sub)}`;
    this.fetch = resolveFetch(config.fetch);
  }

  /** Send one JSON-RPC request and return its `result` (throws on JSON-RPC error). */
  async rpc(method: string, params?: unknown): Promise<unknown> {
    const reqId = ++this.id;
    const payload = JSON.stringify({ jsonrpc: '2.0', id: reqId, method, params });
    const res = await this.fetch(this.url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.config.connectToken}`,
        'content-type': 'application/json',
      },
      body: payload,
    });
    if (!res.ok) throw statusError(res.status, method);
    const text = (await res.text()).trim();
    const line = text.split('\n').find((l) => l.trim().length > 0);
    if (!line) throw new MemoryError(`${method}: empty JSON-RPC response`);
    let msg: { result?: unknown; error?: { code?: number; message?: string } };
    try {
      msg = JSON.parse(line);
    } catch {
      throw new MemoryError(`${method}: malformed JSON-RPC response`);
    }
    if (msg.error) {
      throw new MemoryError(`${method}: ${msg.error.message ?? 'JSON-RPC error'}`, msg.error.code);
    }
    return msg.result;
  }

  /** Invoke one memory.* tool via MCP `tools/call`. */
  async callTool(name: MemoryTool, args: Record<string, unknown> = {}): Promise<unknown> {
    return this.rpc('tools/call', { name, arguments: args });
  }

  recall(args: Record<string, unknown>): Promise<unknown> {
    return this.callTool('memory.recall', args);
  }
  search(args: Record<string, unknown>): Promise<unknown> {
    return this.callTool('memory.search', args);
  }
  neighbors(args: Record<string, unknown>): Promise<unknown> {
    return this.callTool('memory.neighbors', args);
  }
  asOf(args: Record<string, unknown>): Promise<unknown> {
    return this.callTool('memory.as_of', args);
  }
  verify(args: Record<string, unknown>): Promise<unknown> {
    return this.callTool('memory.verify', args);
  }
  critique(args: Record<string, unknown>): Promise<unknown> {
    return this.callTool('memory.critique', args);
  }
  analogy(args: Record<string, unknown>): Promise<unknown> {
    return this.callTool('memory.analogy', args);
  }
  assert(args: Record<string, unknown>): Promise<unknown> {
    return this.callTool('memory.assert', args);
  }
  mergeDiff(args: Record<string, unknown>): Promise<unknown> {
    return this.callTool('memory.merge_diff', args);
  }
  proposeEdge(args: Record<string, unknown>): Promise<unknown> {
    return this.callTool('memory.propose_edge', args);
  }
  confirmEdge(args: Record<string, unknown>): Promise<unknown> {
    return this.callTool('memory.confirm_edge', args);
  }
}
