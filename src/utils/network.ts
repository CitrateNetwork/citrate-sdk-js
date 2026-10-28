/**
 * Network guard: refuse an RPC whose block 0 is not the genesis this SDK's address book
 * was generated for.
 *
 * r1005 and r1006 share chain id 40204, so `eth_chainId` cannot tell them apart. The
 * vendored federation artifact carries `chain.genesisHash` (citrate-chain
 * core/consensus/src/hardening.rs `R1006_GENESIS`), and every path that pairs a book
 * address with an RPC reads block 0 first.
 *
 * Data source: `eth_getBlockByNumber(0)` on the caller's RPC (ethers `getBlock(0)`).
 */
import { CitrateError } from '../errors/CitrateError';
import { FEDERATION_CONTRACT } from '../generated/contract';

const HASH_RE = /^0x[0-9a-f]{64}$/;

/** Block-0 hash of the network the vendored address book describes (r1006). */
export const EXPECTED_GENESIS_HASH: string = FEDERATION_CONTRACT.chain.genesisHash.toLowerCase();

/* istanbul ignore next — build-time invariant */
if (!HASH_RE.test(EXPECTED_GENESIS_HASH)) {
  throw new Error(`network.ts: artifact genesisHash ${EXPECTED_GENESIS_HASH} is not a 32-byte hash`);
}

/** The RPC is on another network than the one the address book is for, or cannot say. */
export class WrongNetworkError extends CitrateError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'WRONG_NETWORK', details);
    this.name = 'WrongNetworkError';
  }
}

/** Anything that can return block 0 with its hash (an ethers Provider qualifies). */
export interface GenesisSource {
  getBlock(tag: number): Promise<{ hash?: string | null } | null>;
}

/**
 * Normalize a caller-supplied expected genesis: `undefined` → the vendored book's genesis,
 * `null` → no check (a dev chain), otherwise a 32-byte hex hash (any case).
 */
export function resolveExpectedGenesis(value: string | null | undefined): string | null {
  if (value === null) return null;
  if (value === undefined) return EXPECTED_GENESIS_HASH;
  const v = String(value).toLowerCase();
  if (!HASH_RE.test(v)) {
    throw new CitrateError(
      `expectedGenesisHash must be a 0x-prefixed 32-byte hex hash or null, got ${String(value)}`,
      'INVALID_ARGUMENT',
    );
  }
  return v;
}

/** Options for {@link assertGenesis}. */
export interface AssertGenesisOptions {
  /** Give up on an endpoint that has not answered block 0 within this many ms (a refusal). */
  timeoutMs?: number;
}

/** How deep FallbackProviders may nest before the shape is refused. */
const MAX_PROVIDER_NESTING = 8;

function unresolvable(why: string): WrongNetworkError {
  return new WrongNetworkError(
    `cannot resolve the RPC provider to its endpoints (${why}); refusing to use the vendored address book`,
  );
}

/**
 * The concrete endpoints behind `source`. An ethers FallbackProvider exposes `providerConfigs`,
 * and each of its providers may itself be a FallbackProvider, so this walks the tree down to
 * the leaves. A cycle, nesting deeper than {@link MAX_PROVIDER_NESTING}, a `providerConfigs`
 * that is not a non-empty list, or an entry without `getBlock` is refused (fail closed).
 */
function endpointsOf(source: GenesisSource): GenesisSource[] {
  const leaves: GenesisSource[] = [];
  const seenLeaves = new Set<GenesisSource>();
  const walk = (node: GenesisSource, ancestors: GenesisSource[]): void => {
    if (ancestors.includes(node)) throw unresolvable('a provider contains itself');
    if (ancestors.length > MAX_PROVIDER_NESTING) {
      throw unresolvable(`nested more than ${MAX_PROVIDER_NESTING} levels deep`);
    }
    const configs = (node as { providerConfigs?: unknown }).providerConfigs;
    if (configs === undefined) {
      if (typeof node.getBlock !== 'function') throw unresolvable('an endpoint cannot report block 0');
      if (!seenLeaves.has(node)) {
        seenLeaves.add(node);
        leaves.push(node);
      }
      return;
    }
    if (!Array.isArray(configs) || configs.length === 0) {
      throw unresolvable('providerConfigs is not a non-empty list');
    }
    for (const c of configs as Array<{ provider?: GenesisSource } | null | undefined>) {
      const child = c?.provider;
      if (!child || typeof child !== 'object') throw unresolvable('a provider entry has no provider');
      walk(child, [...ancestors, node]);
    }
  };
  walk(source, []);
  return leaves;
}

async function readBlock0(source: GenesisSource, timeoutMs: number | undefined) {
  if (timeoutMs === undefined) return source.getBlock(0);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`no answer within ${timeoutMs} ms`)), timeoutMs);
  });
  try {
    return await Promise.race([source.getBlock(0), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function assertOneGenesis(source: GenesisSource, expected: string, timeoutMs: number | undefined): Promise<void> {
  let block: { hash?: string | null } | null;
  try {
    block = await readBlock0(source, timeoutMs);
  } catch (cause) {
    throw new WrongNetworkError(
      `cannot read block 0 from the RPC to verify the network (${(cause as Error)?.message ?? String(cause)}); ` +
        'refusing to use the vendored address book',
      { expected },
    );
  }
  const actual = typeof block?.hash === 'string' ? block.hash.toLowerCase() : '';
  if (!actual) {
    throw new WrongNetworkError('the RPC returned no block 0 hash; refusing to use the vendored address book', {
      expected,
    });
  }
  if (actual !== expected) {
    throw new WrongNetworkError(
      `the RPC is on another network: its block 0 is ${actual}, but this SDK's address book is for ` +
        `genesis ${expected}. Refusing to send or verify against contracts that do not exist there. ` +
        'Point the client at a node of that network, or pass expectedGenesisHash to match yours.',
      { expected, actual },
    );
  }
}

/**
 * Read block 0 from `source` and throw {@link WrongNetworkError} unless its hash is `expected`.
 * Fails closed: an unreadable or missing block 0 is a refusal, not a pass.
 *
 * The guard applies per endpoint. A FallbackProvider answers reads by quorum but broadcasts a
 * signed transaction to every endpoint, so each leaf endpoint (through any nesting of
 * FallbackProviders) must report `expected` itself.
 */
export async function assertGenesis(
  source: GenesisSource,
  expected: string = EXPECTED_GENESIS_HASH,
  options: AssertGenesisOptions = {},
): Promise<void> {
  const endpoints = endpointsOf(source);
  if (endpoints.length === 1) return assertOneGenesis(endpoints[0] as GenesisSource, expected, options.timeoutMs);
  if (endpoints.length === 0) {
    throw new WrongNetworkError('no RPC endpoint to verify the network; refusing to use the vendored address book', {
      expected,
    });
  }
  const results = await Promise.allSettled(endpoints.map((e) => assertOneGenesis(e, expected, options.timeoutMs)));
  const bad = results.findIndex((r) => r.status === 'rejected');
  if (bad >= 0) {
    const reason = (results[bad] as PromiseRejectedResult).reason as WrongNetworkError;
    throw new WrongNetworkError(`RPC endpoint ${bad + 1} of ${endpoints.length}: ${reason.message}`, {
      ...(reason.details ?? { expected }),
      endpoint: bad,
    });
  }
}
