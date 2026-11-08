/**
 * Contract source verification on CitrateScan (chain 40204).
 *
 * Data source: the explorer's Etherscan-compatible API, `GET|POST <explorerUrl>`
 * (default `https://explorer.citrate.ai/api`), `module=contract` with the actions
 * `verifysourcecode` (form-encoded POST) and `checkverifystatus` (GET). Every answer is
 * Etherscan's `{ status: "1" | "0", message, result }` envelope.
 *
 * The request shape is the one forge 1.5.1 (`--verifier custom`) and hardhat-verify 2.1.3 send;
 * `tests/fixtures/verify/` holds their recorded requests and the tests compare against them.
 *
 * Input is a compiler build-info (forge `out/build-info/<id>.json` written with
 * `forge build --build-info`, or hardhat `artifacts/build-info/<id>.json`) or a solc standard
 * JSON input. As forge and hardhat-verify do, only the sources listed in the contract's metadata
 * are submitted.
 */
import { ethers } from 'ethers';
import { CitrateError } from '../errors/CitrateError';
import { enforceTransportSecurity } from '../utils/transport';

/** Etherscan-compatible endpoint of CitrateScan. */
export const DEFAULT_EXPLORER_URL = 'https://explorer.citrate.ai/api';
/** Explorer limits (CitrateScan docs, "Limits"). */
export const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
export const MAX_SOURCE_FILES = 64;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StandardJsonSource {
  content?: string;
  urls?: string[];
  keccak256?: string;
}

/** solc standard JSON input. */
export interface StandardJsonInput {
  language: string;
  sources: Record<string, StandardJsonSource>;
  settings?: Record<string, unknown>;
  [extra: string]: unknown;
}

export interface CompiledContract {
  abi?: unknown[];
  metadata?: string | Record<string, unknown>;
  evm?: { bytecode?: { object?: string; linkReferences?: Record<string, unknown> } };
}

/** A forge or hardhat build-info file. */
export interface BuildInfo {
  _format?: string;
  solcVersion?: string;
  solcLongVersion?: string;
  input: StandardJsonInput;
  output?: { contracts?: Record<string, Record<string, CompiledContract>> };
  [extra: string]: unknown;
}

export interface PreparedSubmission {
  standardJsonInput: StandardJsonInput;
  /** Fully qualified, `path/To.sol:Name`. */
  contractName: string;
  /** `v0.8.26+commit.8a97fa7a`. */
  compilerVersion: string;
}

export type VerifyStatus =
  | { state: 'pending'; message: string }
  | { state: 'verified'; message: string }
  | { state: 'failed'; message: string };

export interface VerifyResult {
  /** `verified` after `Pass - Verified`; `already_verified` when the explorer already has a
   * record; `pending` when called with `wait: false`. */
  status: 'verified' | 'already_verified' | 'pending';
  guid?: string;
  message: string;
  contractName: string;
  compilerVersion: string;
}

export type VerifyFetch = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>;

export interface ExplorerOptions {
  /** Defaults to `https://explorer.citrate.ai/api`. */
  explorerUrl?: string;
  /** Sent as `apikey`. Verification needs no key. */
  apiKey?: string;
  /** Etherscan v2 `chainid`, sent on the submission and every status call when given (CitrateScan
   * accepts 40204). Omit it for an explorer that serves one chain, e.g. a local devnet. */
  chainId?: number;
  fetch?: VerifyFetch;
  /** Allow a remote plaintext `http://` explorer URL (loopback is always allowed). */
  allowInsecureHttp?: boolean;
}

export interface PollOptions {
  /** Default 3000 ms. */
  pollIntervalMs?: number;
  /** Default 300000 ms (compiles may take 120 s, plus queue time). */
  timeoutMs?: number;
  /** Extra submissions after `Max rate limit reached`. Default 3. */
  rateLimitRetries?: number;
  /** Default 5000 ms (one submission per 5 s per IP). */
  rateLimitBackoffMs?: number;
  /** While polling, a transient error (transport failure, HTTP 5xx or 429) is retried after a
   * backoff that starts at `pollIntervalMs`, doubles per consecutive error and is capped here.
   * Default 30000 ms. */
  transientBackoffMaxMs?: number;
}

export interface VerifyContractParams extends ExplorerOptions, PollOptions {
  address: string;
  /** A forge or hardhat build-info (parsed JSON). */
  buildInfo?: BuildInfo;
  /** A solc standard JSON input; needs `contract` as `path:Name` and `compilerVersion`. */
  standardJsonInput?: StandardJsonInput;
  /** `path/To.sol:Name`, or `Name` when unique in the build-info. */
  contract: string;
  /** ABI-encoded constructor arguments, hex. Optional: the explorer reads them from the
   * creation transaction. */
  constructorArgs?: string;
  /** Overrides the version read from the contract metadata. */
  compilerVersion?: string;
  creationTxHash?: string;
  /** Wait for the verdict (default true). */
  wait?: boolean;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class VerificationError extends CitrateError {
  constructor(message: string, code: string, details?: Record<string, unknown>) {
    super(message, code, details);
    this.name = 'VerificationError';
  }
}

/** The build-info or parameters cannot produce a submission. Nothing was sent. */
export class BuildInfoError extends VerificationError {
  constructor(message: string) {
    super(message, 'VERIFY_BAD_INPUT');
    this.name = 'BuildInfoError';
  }
}

/** The explorer refused the submission (`result` is Etherscan's string). */
export class VerificationRejectedError extends VerificationError {
  constructor(readonly result: string) {
    super(`explorer refused the submission: ${result}`, 'VERIFY_REJECTED', { result });
    this.name = 'VerificationRejectedError';
  }
}

/** `Max rate limit reached`, after the configured retries. */
export class VerificationRateLimitedError extends VerificationError {
  constructor(readonly result: string) {
    super(`explorer rate limit: ${result}`, 'VERIFY_RATE_LIMITED', { result });
    this.name = 'VerificationRateLimitedError';
  }
}

/** The explorer compiled the source and it does not match the code on chain. */
export class VerificationFailedError extends VerificationError {
  constructor(readonly guid: string, readonly result: string) {
    super(`verification failed: ${result} (guid ${guid})`, 'VERIFY_FAILED', { guid, result });
    this.name = 'VerificationFailedError';
  }
}

/** No verdict before the deadline. The job may still finish; poll `guid` again later. */
export class VerificationTimeoutError extends VerificationError {
  constructor(readonly guid: string, readonly lastStatus: string) {
    super(`no verdict for ${guid} before the deadline (last: ${lastStatus})`, 'VERIFY_TIMEOUT', { guid, lastStatus });
    this.name = 'VerificationTimeoutError';
  }
}

/**
 * The explorer could not be reached, or answered outside the documented envelope. `transient` is
 * true for a transport failure (connection reset, timeout) and for HTTP 5xx and 429: worth
 * retrying later. `waitForVerification` retries those.
 */
export class ExplorerResponseError extends VerificationError {
  constructor(
    message: string,
    readonly httpStatus?: number,
    readonly transient: boolean = false,
  ) {
    super(message, 'VERIFY_EXPLORER_RESPONSE', httpStatus === undefined ? { transient } : { httpStatus, transient });
    this.name = 'ExplorerResponseError';
  }
}

// ---------------------------------------------------------------------------
// Build-info parsing
// ---------------------------------------------------------------------------

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Accept a forge or hardhat build-info or a bare standard JSON input and return it as a
 * `BuildInfo` (a bare input has no `output`).
 */
export function parseBuildInfo(json: unknown): BuildInfo {
  if (!isObject(json)) throw new BuildInfoError('build-info is not a JSON object');
  if (json._format === 'hh-sol-artifact-1') {
    throw new BuildInfoError(
      'this is a hardhat contract artifact; pass the build-info it names in the sibling .dbg.json (or use loadBuildInfo(path))',
    );
  }
  if (isObject(json.input)) return json as unknown as BuildInfo;
  if ('source_id_to_path' in json) {
    throw new BuildInfoError(
      'this forge build-info has no compiler input; rebuild with `forge build --build-info` (or build_info = true in foundry.toml)',
    );
  }
  if (isObject(json.sources) && typeof json.language === 'string') {
    return { input: json as unknown as StandardJsonInput };
  }
  throw new BuildInfoError('not a forge or hardhat build-info or a standard JSON input');
}

/**
 * Node only: read a build-info from disk. Also accepts a hardhat contract artifact
 * (`artifacts/<path>/<Name>.json`) and follows its `.dbg.json` to the build-info; the
 * returned `contract` is then the artifact's `sourceName:contractName`.
 */
export async function loadBuildInfo(path: string): Promise<{ buildInfo: BuildInfo; contract?: string }> {
  const fs = await import('node:fs/promises');
  const nodePath = await import('node:path');
  const read = async (p: string): Promise<unknown> => {
    try {
      return JSON.parse(await fs.readFile(p, 'utf8'));
    } catch (e) {
      throw new BuildInfoError(`cannot read ${p}: ${(e as Error).message}`);
    }
  };
  const json = await read(path);
  if (isObject(json) && json._format === 'hh-sol-artifact-1') {
    const { sourceName, contractName } = json;
    if (typeof sourceName !== 'string' || typeof contractName !== 'string') {
      throw new BuildInfoError('hardhat artifact has no sourceName/contractName');
    }
    const dbgPath = path.replace(/\.json$/, '.dbg.json');
    const dbg = await read(dbgPath);
    if (!isObject(dbg) || typeof dbg.buildInfo !== 'string') {
      throw new BuildInfoError(`${dbgPath} names no buildInfo`);
    }
    const bi = parseBuildInfo(await read(nodePath.resolve(nodePath.dirname(dbgPath), dbg.buildInfo)));
    return { buildInfo: bi, contract: `${sourceName}:${contractName}` };
  }
  return { buildInfo: parseBuildInfo(json) };
}

/** `0.8.26+commit.8a97fa7a` or `v0.8.26+commit.8a97fa7a` → `v0.8.26+commit.8a97fa7a`. */
export function normalizeCompilerVersion(v: string): string {
  const t = v.trim().replace(/^v/, '');
  if (!t.includes('+commit.')) {
    throw new BuildInfoError(`compiler version ${JSON.stringify(v)} lacks the commit; use e.g. v0.8.26+commit.8a97fa7a`);
  }
  return `v${t}`;
}

/** Validate hex constructor arguments; return them lowercase without `0x`. */
export function normalizeConstructorArgs(args: string): string {
  const t = args.trim().replace(/^0x/i, '');
  if (t.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(t)) {
    throw new BuildInfoError('constructorArgs must be ABI-encoded hex');
  }
  return t.toLowerCase();
}

function resolveContract(bi: BuildInfo, wanted: string): [string, string] {
  const contracts = bi.output?.contracts;
  const idx = wanted.lastIndexOf(':');
  if (idx >= 0) {
    const path = wanted.slice(0, idx);
    const name = wanted.slice(idx + 1);
    if (contracts && !contracts[path]?.[name]) {
      throw new BuildInfoError(`contract ${wanted} is not in this build-info`);
    }
    return [path, name];
  }
  if (!contracts) {
    throw new BuildInfoError('a standard JSON input carries no contract list; pass contract as path:Name');
  }
  const hits: [string, string][] = [];
  for (const [path, file] of Object.entries(contracts)) {
    for (const name of Object.keys(file)) if (name === wanted) hits.push([path, name]);
  }
  if (hits.length === 1) return hits[0] as [string, string];
  if (hits.length === 0) throw new BuildInfoError(`contract ${wanted} is not in this build-info`);
  throw new BuildInfoError(`several contracts are named ${wanted}: ${hits.map(([p, n]) => `${p}:${n}`).join(', ')}`);
}

function metadataOf(bi: BuildInfo, path: string, name: string): Record<string, unknown> | undefined {
  const raw = bi.output?.contracts?.[path]?.[name]?.metadata;
  if (typeof raw === 'string') {
    try {
      const parsed: unknown = JSON.parse(raw);
      return isObject(parsed) ? parsed : undefined;
    } catch {
      throw new BuildInfoError(`metadata of ${path}:${name} is not JSON`);
    }
  }
  return isObject(raw) ? raw : undefined;
}

/**
 * The standard JSON input, fully qualified name and compiler version for one contract.
 * The compiler version comes from the contract metadata (forge writes `solcLongVersion`
 * without the commit).
 */
export function prepareStandardJson(
  bi: BuildInfo,
  contract: string,
  compilerVersion?: string,
): PreparedSubmission {
  const [path, name] = resolveContract(bi, contract);
  const meta = metadataOf(bi, path, name);
  const metaCompiler = isObject(meta?.compiler) ? (meta?.compiler as Record<string, unknown>).version : undefined;
  const version =
    compilerVersion ??
    (typeof metaCompiler === 'string' ? metaCompiler : undefined) ??
    bi.solcLongVersion;
  if (!version) throw new BuildInfoError('no compiler version in the build-info; pass compilerVersion');

  const all = bi.input.sources;
  if (!isObject(all)) throw new BuildInfoError('standard JSON input has no sources');
  const keep = isObject(meta?.sources) ? Object.keys(meta?.sources as object) : Object.keys(all);
  const sources: Record<string, StandardJsonSource> = {};
  for (const key of keep) {
    const src = all[key];
    if (!src) throw new BuildInfoError(`source ${key} is in the metadata but not in the input`);
    if (typeof src.content !== 'string') {
      throw new BuildInfoError(`source ${key} has no inline content (the explorer does not fetch urls)`);
    }
    sources[key] = src;
  }
  if (Object.keys(sources).length > MAX_SOURCE_FILES) {
    throw new BuildInfoError(`${Object.keys(sources).length} source files; the explorer accepts at most ${MAX_SOURCE_FILES}`);
  }

  const settings: Record<string, unknown> = { ...(bi.input.settings ?? {}) };
  const sel = settings.outputSelection;
  if (isObject(sel) && !('*' in sel)) {
    // forge keys outputSelection by file; the pruned input uses one "*" entry.
    const first = Object.values(sel)[0];
    if (first !== undefined) settings.outputSelection = { '*': first };
  }
  if (!('libraries' in settings)) settings.libraries = {};

  const standardJsonInput: StandardJsonInput = {
    language: typeof bi.input.language === 'string' ? bi.input.language : 'Solidity',
    sources,
    settings,
  };
  const size = new TextEncoder().encode(JSON.stringify(standardJsonInput)).length;
  if (size > MAX_SOURCE_BYTES) {
    throw new BuildInfoError(`standard JSON input is ${size} bytes; the explorer accepts at most ${MAX_SOURCE_BYTES}`);
  }
  return { standardJsonInput, contractName: `${path}:${name}`, compilerVersion: normalizeCompilerVersion(version) };
}

// ---------------------------------------------------------------------------
// Request shape
// ---------------------------------------------------------------------------

function checkAddress(a: string): void {
  if (!/^0x[0-9a-fA-F]{40}$/.test(a)) throw new BuildInfoError(`address ${JSON.stringify(a)} is not 20 bytes of hex`);
}

/**
 * The `verifysourcecode` form fields, in the order forge sends them. Constructor arguments go
 * out as both `constructorArguements` (Etherscan's spelling) and `constructorArguments`.
 */
export function buildVerifySourceCodeForm(p: {
  address: string;
  submission: PreparedSubmission;
  constructorArgs?: string;
  creationTxHash?: string;
  chainId?: number;
  apiKey?: string;
}): [string, string][] {
  checkAddress(p.address);
  const f: [string, string][] = [];
  if (p.apiKey) f.push(['apikey', p.apiKey]);
  if (p.chainId !== undefined) f.push(['chainid', String(p.chainId)]);
  f.push(
    ['module', 'contract'],
    ['action', 'verifysourcecode'],
    ['contractaddress', p.address],
    ['sourceCode', JSON.stringify(p.submission.standardJsonInput)],
    ['codeformat', 'solidity-standard-json-input'],
    ['contractname', p.submission.contractName],
    ['compilerversion', normalizeCompilerVersion(p.submission.compilerVersion)],
  );
  if (p.constructorArgs !== undefined && p.constructorArgs !== '') {
    const hex = normalizeConstructorArgs(p.constructorArgs);
    f.push(['constructorArguements', hex], ['constructorArguments', hex]);
  }
  if (p.creationTxHash) f.push(['creationtxhash', p.creationTxHash]);
  return f;
}

function encodeForm(fields: [string, string][]): string {
  return new URLSearchParams(fields).toString();
}

// ---------------------------------------------------------------------------
// Explorer calls
// ---------------------------------------------------------------------------

interface Envelope {
  ok: boolean;
  message: string;
  result: unknown;
}

function resultText(e: Envelope): string {
  return typeof e.result === 'string' ? e.result : JSON.stringify(e.result);
}

const isRateLimit = (s: string): boolean => /rate limit/i.test(s);

function explorerBase(o: ExplorerOptions): string {
  return enforceTransportSecurity(o.explorerUrl ?? DEFAULT_EXPLORER_URL, {
    allowInsecureHttp: o.allowInsecureHttp ?? false,
  });
}

function fetchOf(o: ExplorerOptions): VerifyFetch {
  const f = o.fetch ?? (globalThis.fetch as unknown as VerifyFetch | undefined);
  if (!f) throw new ExplorerResponseError('no fetch implementation available; pass options.fetch');
  return f;
}

async function call(o: ExplorerOptions, url: string, init?: Parameters<VerifyFetch>[1]): Promise<Envelope> {
  let res: Awaited<ReturnType<VerifyFetch>>;
  try {
    res = await fetchOf(o)(url, init);
  } catch (e) {
    throw new ExplorerResponseError(`could not reach the explorer: ${(e as Error).message}`, undefined, true);
  }
  const text = await res.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  if (isObject(body) && (typeof body.status === 'string' || typeof body.status === 'number')) {
    return {
      ok: String(body.status) === '1',
      message: typeof body.message === 'string' ? body.message : '',
      result: body.result,
    };
  }
  if (!res.ok) {
    const transient = res.status >= 500 || res.status === 429;
    throw new ExplorerResponseError(`explorer answered HTTP ${res.status}: ${text.slice(0, 300)}`, res.status, transient);
  }
  throw new ExplorerResponseError(`unexpected explorer answer: ${text.slice(0, 300)}`, res.status);
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Submit once; returns the guid. Throws `VerificationRejectedError` / `VerificationRateLimitedError`. */
export async function submitVerification(
  form: [string, string][],
  o: ExplorerOptions & PollOptions = {},
): Promise<string> {
  const url = explorerBase(o);
  const retries = o.rateLimitRetries ?? 3;
  for (let attempt = 0; ; attempt++) {
    const env = await call(o, url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: encodeForm(form),
    });
    const text = resultText(env);
    if (env.ok) {
      if (!text) throw new ExplorerResponseError('empty guid');
      return text;
    }
    if (isRateLimit(text) && attempt < retries) {
      await sleep(o.rateLimitBackoffMs ?? 5000);
      continue;
    }
    if (isRateLimit(text)) throw new VerificationRateLimitedError(text);
    throw new VerificationRejectedError(text);
  }
}

/** One `checkverifystatus` call. */
export async function checkVerifyStatus(guid: string, o: ExplorerOptions = {}): Promise<VerifyStatus> {
  const q: [string, string][] = [];
  if (o.apiKey) q.push(['apikey', o.apiKey]);
  if (o.chainId !== undefined) q.push(['chainid', String(o.chainId)]);
  q.push(['module', 'contract'], ['action', 'checkverifystatus'], ['guid', guid]);
  const env = await call(o, `${explorerBase(o)}?${encodeForm(q)}`, { method: 'GET' });
  const text = resultText(env);
  if (env.ok || /already verified/i.test(text)) return { state: 'verified', message: text };
  if (/^pending/i.test(text) || isRateLimit(text)) return { state: 'pending', message: text };
  return { state: 'failed', message: text };
}

/**
 * Poll until `Pass - Verified` (resolves) or `Fail - …` (throws `VerificationFailedError`).
 *
 * A transient `ExplorerResponseError` (transport failure, HTTP 5xx or 429) does not end the wait:
 * the poll is retried after a backoff that doubles from `pollIntervalMs` up to
 * `transientBackoffMaxMs`, within `timeoutMs`. Any other error ends it.
 */
export async function waitForVerification(guid: string, o: ExplorerOptions & PollOptions = {}): Promise<VerifyStatus> {
  const interval = o.pollIntervalMs ?? 3000;
  const backoffMax = o.transientBackoffMaxMs ?? 30_000;
  const deadline = Date.now() + (o.timeoutMs ?? 300_000);
  let transientErrors = 0;
  for (;;) {
    let delay = interval;
    let last: string;
    try {
      const s = await checkVerifyStatus(guid, o);
      if (s.state === 'verified') return s;
      if (s.state === 'failed') throw new VerificationFailedError(guid, s.message);
      transientErrors = 0;
      last = s.message;
    } catch (e) {
      if (!(e instanceof ExplorerResponseError) || !e.transient) throw e;
      transientErrors++;
      delay = Math.min(interval * 2 ** (transientErrors - 1), Math.max(backoffMax, interval));
      last = e.message;
    }
    if (Date.now() + delay > deadline) throw new VerificationTimeoutError(guid, last);
    await sleep(delay);
  }
}

/**
 * Verify a deployed contract's source on CitrateScan.
 *
 * Submits `verifysourcecode` and, unless `wait: false`, polls `checkverifystatus` until a
 * verdict. Resolves `verified` or `already_verified`; throws `VerificationFailedError` on
 * `Fail - Unable to verify`, and the other `VerificationError` subclasses otherwise.
 */
export async function verifyContract(p: VerifyContractParams): Promise<VerifyResult> {
  if (p.chainId !== undefined && (!Number.isInteger(p.chainId) || p.chainId <= 0)) {
    throw new BuildInfoError('chainId must be a positive integer');
  }
  const source = p.buildInfo ?? (p.standardJsonInput ? { input: p.standardJsonInput } : undefined);
  if (!source) throw new BuildInfoError('pass buildInfo or standardJsonInput');
  const submission = prepareStandardJson(parseBuildInfo(source), p.contract, p.compilerVersion);
  const form = buildVerifySourceCodeForm({
    address: p.address,
    submission,
    ...(p.constructorArgs !== undefined ? { constructorArgs: p.constructorArgs } : {}),
    ...(p.creationTxHash !== undefined ? { creationTxHash: p.creationTxHash } : {}),
    ...(p.chainId !== undefined ? { chainId: p.chainId } : {}),
    ...(p.apiKey !== undefined ? { apiKey: p.apiKey } : {}),
  });
  const base = { contractName: submission.contractName, compilerVersion: submission.compilerVersion };
  let guid: string;
  try {
    guid = await submitVerification(form, p);
  } catch (e) {
    if (e instanceof VerificationRejectedError && /already verified/i.test(e.result)) {
      return { status: 'already_verified', message: e.result, ...base };
    }
    throw e;
  }
  if (p.wait === false) return { status: 'pending', guid, message: 'submitted', ...base };
  const s = await waitForVerification(guid, p);
  return { status: 'verified', guid, message: s.message, ...base };
}

// ---------------------------------------------------------------------------
// Deploy, then verify
// ---------------------------------------------------------------------------

/** What `deployAndVerify` needs from a client; `CitrateClient` provides it. */
export interface ContractDeployer {
  deployContract(p: { data: string; value?: bigint; gasLimit?: bigint }): Promise<{ address: string; txHash: string }>;
}

export interface DeployAndVerifyParams extends Omit<VerifyContractParams, 'address' | 'constructorArgs' | 'creationTxHash'> {
  /** Signs and sends the creation transaction (e.g. a `CitrateClient` with a private key). */
  client: ContractDeployer;
  /** Constructor arguments as values, ABI-encoded with the contract's ABI from the build-info. */
  args?: readonly unknown[];
  /** Or already-encoded constructor arguments (hex). */
  constructorArgs?: string;
  value?: bigint;
  gasLimit?: bigint;
  /** How long to retry while the explorer has not indexed the new contract. Default 120000 ms. */
  indexTimeoutMs?: number;
}

export interface DeployAndVerifyResult {
  address: string;
  txHash: string;
  verification: VerifyResult;
}

/**
 * Deploy a contract from a build-info through the client's signer, then verify it.
 *
 * The creation code is the build-info's `evm.bytecode.object` (unlinked libraries are refused)
 * followed by the constructor arguments. The creation transaction hash is passed to the
 * explorer. While the explorer answers `Unable to locate ContractCode` (not indexed yet), the
 * submission is retried until `indexTimeoutMs`.
 */
export async function deployAndVerify(p: DeployAndVerifyParams): Promise<DeployAndVerifyResult> {
  if (!p.buildInfo) throw new BuildInfoError('deployAndVerify needs buildInfo (it carries the bytecode)');
  const bi = parseBuildInfo(p.buildInfo);
  const [path, name] = resolveContract(bi, p.contract);
  const compiled = bi.output?.contracts?.[path]?.[name];
  const bytecode = compiled?.evm?.bytecode?.object;
  if (!bytecode) throw new BuildInfoError(`${path}:${name} has no evm.bytecode.object in the build-info`);
  if (bytecode.includes('__$')) throw new BuildInfoError(`${path}:${name} has unlinked library placeholders; link them first`);
  if (p.args && p.constructorArgs) throw new BuildInfoError('pass args or constructorArgs, not both');

  let encodedArgs = p.constructorArgs ? normalizeConstructorArgs(p.constructorArgs) : '';
  if (p.args) {
    if (!Array.isArray(compiled?.abi)) throw new BuildInfoError(`${path}:${name} has no ABI to encode args with`);
    const iface = new ethers.Interface(compiled.abi as ethers.InterfaceAbi);
    encodedArgs = iface.encodeDeploy(p.args as unknown[]).replace(/^0x/, '');
  }
  const data = `0x${bytecode.replace(/^0x/, '')}${encodedArgs}`;
  const deployed = await p.client.deployContract({
    data,
    ...(p.value !== undefined ? { value: p.value } : {}),
    ...(p.gasLimit !== undefined ? { gasLimit: p.gasLimit } : {}),
  });

  const { client: _c, args: _a, value: _v, gasLimit: _g, indexTimeoutMs, ...verifyParams } = p;
  const params: VerifyContractParams = {
    ...verifyParams,
    contract: `${path}:${name}`,
    address: deployed.address,
    creationTxHash: deployed.txHash,
    ...(encodedArgs ? { constructorArgs: encodedArgs } : {}),
  };
  const indexDeadline = Date.now() + (indexTimeoutMs ?? 120_000);
  for (;;) {
    try {
      const verification = await verifyContract(params);
      return { address: deployed.address, txHash: deployed.txHash, verification };
    } catch (e) {
      const notIndexed = e instanceof VerificationRejectedError && /unable to locate contractcode/i.test(e.result);
      if (!notIndexed || Date.now() >= indexDeadline) throw e;
      await sleep(p.pollIntervalMs ?? 3000);
    }
  }
}
