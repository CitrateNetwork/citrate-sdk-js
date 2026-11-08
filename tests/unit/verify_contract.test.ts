/**
 * verifyContract / deployAndVerify against the explorer's Etherscan-compatible API.
 *
 * The HTTP server here is a test-only recorder (Rule 1 allows test fakes). The request shapes
 * it checks come from real tools: tests/fixtures/verify/*\/…-requests.jsonl are the requests
 * forge 1.5.1 and hardhat-verify 2.1.3 sent to a recording server, and the build-info files were
 * written by those tools' compilers (see the README there).
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ethers } from 'ethers';
import * as sdk from '../../src';
import {
  verifyContract,
  deployAndVerify,
  loadBuildInfo,
  parseBuildInfo,
  prepareStandardJson,
  buildVerifySourceCodeForm,
  checkVerifyStatus,
  waitForVerification,
  BuildInfoError,
  VerificationFailedError,
  VerificationRejectedError,
  VerificationRateLimitedError,
  VerificationTimeoutError,
  ExplorerResponseError,
  DEFAULT_EXPLORER_URL,
  DEFAULT_EXPLORER_REQUEST_TIMEOUT_MS,
  type BuildInfo,
  type ContractDeployer,
  type VerifyFetch,
} from '../../src/verify';

const FX = join(__dirname, '..', 'fixtures', 'verify');
const FORGE_BI = join(FX, 'forge', 'build-info', '970692f6b0ae96cc.json');
const HH_BI = join(FX, 'hardhat', 'artifacts', 'build-info', 'dd99b6a8e0696988f72849c906423ccc.json');
const HH_ARTIFACT = join(FX, 'hardhat', 'artifacts', 'contracts', 'Greeter.sol', 'Greeter.json');
const FORGE_ADDR = '0x5fbdb2315678afecb367f032d99f2f9fc9a2f74b';
const HH_ADDR = '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512';
const GUID = '5d1d6cbe-5f4d-4bd4-a1c9-2c1a1c5b1e01';

const json = (p: string): unknown => JSON.parse(readFileSync(p, 'utf8'));
const forgeBuildInfo = (): BuildInfo => json(FORGE_BI) as BuildInfo;

interface Recorded {
  method: string;
  path: string;
  fields: [string, string][];
}

function recorded(file: string): Recorded[] {
  return readFileSync(join(FX, file), 'utf8')
    .trim()
    .split('\n')
    .map((l) => {
      const v = JSON.parse(l) as { method: string; path: string; body: string };
      return { method: v.method, path: v.path, fields: [...new URLSearchParams(v.body)] };
    });
}

/** Fields as a map; sourceCode compared as parsed JSON. */
function normalized(fields: [string, string][]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of fields) out[k] = k === 'sourceCode' ? JSON.parse(v) : v;
  return out;
}

// ---------------------------------------------------------------------------
// test-only HTTP recorder
// ---------------------------------------------------------------------------

interface Seen {
  method: string;
  url: string;
  contentType: string | undefined;
  body: string;
  /** Date.now() when the request arrived. */
  at: number;
}

/** Script status RESET: drop the connection without answering. HANG: never answer. */
const RESET = 0;
const HANG = -1;

async function recorder(script: [number, string][]): Promise<{ url: string; seen: Seen[]; close: () => Promise<void> }> {
  const seen: Seen[] = [];
  const queue = [...script];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c.toString('utf8')));
    req.on('end', () => {
      seen.push({ method: req.method ?? '', url: req.url ?? '', contentType: req.headers['content-type'], body, at: Date.now() });
      const [status, answer] = (queue.length > 1 ? queue.shift() : queue[0]) ?? [200, '{}'];
      if (status === RESET) {
        req.socket.destroy();
        return;
      }
      if (status === HANG) return;
      res.writeHead(status, { 'content-type': 'application/json', connection: 'close' });
      res.end(answer);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/api`,
    seen,
    close: () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

const OK_GUID = JSON.stringify({ status: '1', message: 'OK', result: GUID });
const PENDING = JSON.stringify({ status: '0', message: 'NOTOK', result: 'Pending in queue' });
const PASS = JSON.stringify({ status: '1', message: 'OK', result: 'Pass - Verified' });
const FAIL = JSON.stringify({ status: '0', message: 'NOTOK', result: 'Fail - Unable to verify' });
const fast = { pollIntervalMs: 5, timeoutMs: 5000, rateLimitBackoffMs: 5, rateLimitRetries: 2 };

const query = (s: Seen): Record<string, string> =>
  Object.fromEntries(new URLSearchParams(s.url.split('?')[1] ?? ''));

// ---------------------------------------------------------------------------
// build-info parsing
// ---------------------------------------------------------------------------

describe('build-info parsing', () => {
  it('forge build-info gives the standard JSON forge itself submits', () => {
    const s = prepareStandardJson(forgeBuildInfo(), 'src/Greeter.sol:Greeter');
    expect(s.contractName).toBe('src/Greeter.sol:Greeter');
    // forge writes solcLongVersion "0.8.26"; the commit comes from the contract metadata.
    expect(s.compilerVersion).toBe('v0.8.26+commit.8a97fa7a');
    expect(s.standardJsonInput).toEqual(json(join(FX, 'forge', 'standard-json-input.json')));
    expect(Object.keys(s.standardJsonInput.sources)).not.toContain('src/Unrelated.sol');
    for (const extra of ['version', 'allowPaths', 'basePath', 'includePaths']) {
      expect(s.standardJsonInput).not.toHaveProperty(extra);
    }
  });

  it('resolves a bare contract name when unique, and refuses unknown names', () => {
    expect(prepareStandardJson(forgeBuildInfo(), 'Greeter').contractName).toBe('src/Greeter.sol:Greeter');
    expect(() => prepareStandardJson(forgeBuildInfo(), 'Nope')).toThrow(/not in this build-info/);
  });

  it('a plain forge build-info (no --build-info) is refused with the fix', () => {
    expect(() => parseBuildInfo(json(join(FX, 'forge', 'minimal-build-info.json')))).toThrow(/forge build --build-info/);
  });

  it('hardhat artifact resolves its build-info and gives what hardhat-verify submits', async () => {
    const { buildInfo, contract } = await loadBuildInfo(HH_ARTIFACT);
    expect(contract).toBe('contracts/Greeter.sol:Greeter');
    const s = prepareStandardJson(buildInfo, contract as string);
    expect(s.compilerVersion).toBe('v0.8.26+commit.8a97fa7a');
    const hh = recorded('hardhat/hardhat-verify-2.1.3-requests.jsonl').find((r) => r.method === 'POST') as Recorded;
    expect(normalized(hh.fields).sourceCode).toEqual(s.standardJsonInput);
  });

  it('hardhat build-info with a bare name', async () => {
    const { buildInfo } = await loadBuildInfo(HH_BI);
    expect(prepareStandardJson(buildInfo, 'Greeter').contractName).toBe('contracts/Greeter.sol:Greeter');
  });

  it('a hardhat artifact passed as JSON points to loadBuildInfo', () => {
    expect(() => parseBuildInfo(json(HH_ARTIFACT))).toThrow(/dbg\.json/);
  });

  it('a bare standard JSON input needs path:Name and a long compiler version', () => {
    const std = json(join(FX, 'forge', 'standard-json-input.json'));
    const bi = parseBuildInfo(std);
    expect(() => prepareStandardJson(bi, 'Greeter', 'v0.8.26+commit.8a97fa7a')).toThrow(/path:Name/);
    expect(() => prepareStandardJson(bi, 'src/Greeter.sol:Greeter')).toThrow(/compiler version/);
    expect(() => prepareStandardJson(bi, 'src/Greeter.sol:Greeter', '0.8.26')).toThrow(/commit/);
    expect(prepareStandardJson(bi, 'src/Greeter.sol:Greeter', '0.8.26+commit.8a97fa7a').standardJsonInput).toEqual(std);
  });

  it('url-only sources are refused', () => {
    const std = json(join(FX, 'forge', 'standard-json-input.json')) as { sources: Record<string, unknown> };
    std.sources['src/Counter.sol'] = { urls: ['ipfs://x'] };
    expect(() => prepareStandardJson(parseBuildInfo(std), 'src/Greeter.sol:Greeter', 'v0.8.26+commit.8a97fa7a')).toThrow(
      /inline content/,
    );
  });
});

// ---------------------------------------------------------------------------
// request shape
// ---------------------------------------------------------------------------

describe('request shape', () => {
  it('matches the request forge --verifier custom sends', () => {
    const submission = prepareStandardJson(forgeBuildInfo(), 'src/Greeter.sol:Greeter');
    const ours = buildVerifySourceCodeForm({
      address: FORGE_ADDR,
      submission,
      constructorArgs: '0x0000000000000000000000000000000000000000000000000000000000000007',
    });
    const forge = recorded('forge/forge-1.5.1-custom-verifier-requests.jsonl')[0] as Recorded;
    expect([forge.method, forge.path]).toEqual(['POST', '/api']);
    expect(normalized(ours)).toEqual(normalized(forge.fields));
  });

  it("uses Etherscan's constructorArguements spelling, without 0x", () => {
    const submission = prepareStandardJson(forgeBuildInfo(), 'Greeter');
    const f = Object.fromEntries(buildVerifySourceCodeForm({ address: FORGE_ADDR, submission, constructorArgs: '0xABCD' }));
    expect(f.constructorArguements).toBe('abcd');
    expect(f.constructorArguments).toBe('abcd');
    const none = Object.fromEntries(buildVerifySourceCodeForm({ address: FORGE_ADDR, submission }));
    expect(none).not.toHaveProperty('constructorArguements');
    expect(() => buildVerifySourceCodeForm({ address: FORGE_ADDR, submission, constructorArgs: '0xabc' })).toThrow(BuildInfoError);
    expect(() => buildVerifySourceCodeForm({ address: '0x1234', submission })).toThrow(BuildInfoError);
  });
});

// ---------------------------------------------------------------------------
// verifyContract against a recorder
// ---------------------------------------------------------------------------

describe('verifyContract', () => {
  it('submits, polls Pending → Pass, and resolves verified', async () => {
    const srv = await recorder([[200, OK_GUID], [200, PENDING], [200, PENDING], [200, PASS]]);
    try {
      const r = await verifyContract({
        chainId: 40204,
        address: FORGE_ADDR,
        buildInfo: forgeBuildInfo(),
        contract: 'src/Greeter.sol:Greeter',
        constructorArgs: '0x07',
        explorerUrl: srv.url,
        apiKey: 'citrate',
        ...fast,
      });
      expect(r).toEqual({
        status: 'verified',
        guid: GUID,
        message: 'Pass - Verified',
        contractName: 'src/Greeter.sol:Greeter',
        compilerVersion: 'v0.8.26+commit.8a97fa7a',
      });
      expect(srv.seen).toHaveLength(4);
      const post = srv.seen[0] as Seen;
      expect([post.method, post.url, post.contentType]).toEqual(['POST', '/api', 'application/x-www-form-urlencoded']);
      const body = Object.fromEntries(new URLSearchParams(post.body));
      expect(body).toMatchObject({
        apikey: 'citrate',
        chainid: '40204',
        module: 'contract',
        action: 'verifysourcecode',
        contractaddress: FORGE_ADDR,
        codeformat: 'solidity-standard-json-input',
        contractname: 'src/Greeter.sol:Greeter',
        compilerversion: 'v0.8.26+commit.8a97fa7a',
        constructorArguements: '07',
      });
      for (const s of srv.seen.slice(1)) {
        expect(s.method).toBe('GET');
        expect(query(s)).toEqual({ apikey: 'citrate', chainid: '40204', module: 'contract', action: 'checkverifystatus', guid: GUID });
      }
    } finally {
      await srv.close();
    }
  });

  it('without chainId sends no chainid on the submission or any status call (local devnets)', async () => {
    const srv = await recorder([[200, OK_GUID], [200, PENDING], [200, PASS]]);
    try {
      const r = await verifyContract({
        address: FORGE_ADDR,
        buildInfo: forgeBuildInfo(),
        contract: 'Greeter',
        explorerUrl: srv.url,
        apiKey: 'citrate',
        ...fast,
      });
      expect(r.status).toBe('verified');
      expect(srv.seen).toHaveLength(3);
      expect(Object.fromEntries(new URLSearchParams((srv.seen[0] as Seen).body))).not.toHaveProperty('chainid');
      for (const s of srv.seen.slice(1)) {
        expect(query(s)).toEqual({ apikey: 'citrate', module: 'contract', action: 'checkverifystatus', guid: GUID });
      }
    } finally {
      await srv.close();
    }
  });

  it('a chainId other than 40204 is sent as given; a non-positive one is refused', async () => {
    const srv = await recorder([[200, OK_GUID], [200, PASS]]);
    try {
      await verifyContract({ chainId: 1337, address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: srv.url, ...fast });
      expect(Object.fromEntries(new URLSearchParams((srv.seen[0] as Seen).body)).chainid).toBe('1337');
      expect(query(srv.seen[1] as Seen).chainid).toBe('1337');
    } finally {
      await srv.close();
    }
    for (const bad of [0, -1, 1.5]) {
      await expect(verifyContract({ chainId: bad, address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter' })).rejects.toBeInstanceOf(
        BuildInfoError,
      );
    }
  });

  it('sends what hardhat-verify sends (plus chainid and the corrected spelling)', async () => {
    const srv = await recorder([[200, OK_GUID]]);
    try {
      const { buildInfo, contract } = await loadBuildInfo(HH_ARTIFACT);
      const hh = recorded('hardhat/hardhat-verify-2.1.3-requests.jsonl').find((r) => r.method === 'POST') as Recorded;
      const hhMap = Object.fromEntries(hh.fields);
      await verifyContract({
        chainId: 40204,
        address: HH_ADDR,
        buildInfo,
        contract: contract as string,
        constructorArgs: hhMap.constructorArguements as string,
        explorerUrl: srv.url,
        apiKey: 'citrate',
        wait: false,
      });
      const ours = normalized([...new URLSearchParams((srv.seen[0] as Seen).body)]);
      expect(ours.chainid).toBe('40204');
      expect(ours.constructorArguments).toBe(hhMap.constructorArguements);
      delete ours.chainid;
      delete ours.constructorArguments;
      expect(ours).toEqual(normalized(hh.fields));
    } finally {
      await srv.close();
    }
  });

  it('wait:false returns the guid without polling', async () => {
    const srv = await recorder([[200, OK_GUID]]);
    try {
      const r = await verifyContract({ chainId: 40204, address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: srv.url, wait: false });
      expect(r.status).toBe('pending');
      expect(r.guid).toBe(GUID);
      expect(srv.seen).toHaveLength(1);
      expect(Object.fromEntries(new URLSearchParams((srv.seen[0] as Seen).body))).not.toHaveProperty('apikey');
    } finally {
      await srv.close();
    }
  });

  it('accepts a standard JSON input', async () => {
    const srv = await recorder([[200, OK_GUID], [200, PASS]]);
    try {
      const r = await verifyContract({
        chainId: 40204,
        address: FORGE_ADDR,
        standardJsonInput: json(join(FX, 'forge', 'standard-json-input.json')) as sdk.StandardJsonInput,
        contract: 'src/Greeter.sol:Greeter',
        compilerVersion: 'v0.8.26+commit.8a97fa7a',
        explorerUrl: srv.url,
        ...fast,
      });
      expect(r.status).toBe('verified');
    } finally {
      await srv.close();
    }
  });

  it('Fail - Unable to verify throws VerificationFailedError', async () => {
    const srv = await recorder([[200, OK_GUID], [200, PENDING], [200, FAIL]]);
    try {
      const p = verifyContract({ chainId: 40204, address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: srv.url, ...fast });
      await expect(p).rejects.toBeInstanceOf(VerificationFailedError);
      await expect(p).rejects.toMatchObject({ guid: GUID, result: 'Fail - Unable to verify', code: 'VERIFY_FAILED' });
    } finally {
      await srv.close();
    }
  });

  it('times out with the last status', async () => {
    const srv = await recorder([[200, OK_GUID], [200, PENDING]]);
    try {
      const p = verifyContract({ chainId: 40204, address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: srv.url, pollIntervalMs: 5, timeoutMs: 60 });
      await expect(p).rejects.toBeInstanceOf(VerificationTimeoutError);
      await expect(p).rejects.toMatchObject({ guid: GUID, lastStatus: 'Pending in queue' });
    } finally {
      await srv.close();
    }
  });

  it('a connection reset, a 5xx and a 429 while polling do not end the wait', async () => {
    const srv = await recorder([[200, OK_GUID], [RESET, ''], [503, 'Service Unavailable'], [429, 'Too Many Requests'], [200, PASS]]);
    try {
      const r = await verifyContract({ address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: srv.url, ...fast });
      expect(r).toMatchObject({ status: 'verified', guid: GUID, message: 'Pass - Verified' });
      expect(srv.seen).toHaveLength(5);
    } finally {
      await srv.close();
    }
  });

  it('a 4xx other than 429 while polling ends the wait', async () => {
    const srv = await recorder([[200, OK_GUID], [404, 'not found'], [200, PASS]]);
    try {
      const p = verifyContract({ address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: srv.url, ...fast });
      await expect(p).rejects.toBeInstanceOf(ExplorerResponseError);
      await expect(p).rejects.toMatchObject({ httpStatus: 404, transient: false });
      expect(srv.seen).toHaveLength(2);
    } finally {
      await srv.close();
    }
  });

  it('transient errors until the deadline end in VerificationTimeoutError', async () => {
    const srv = await recorder([[200, OK_GUID], [503, 'Service Unavailable']]);
    try {
      const p = verifyContract({ address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: srv.url, pollIntervalMs: 5, timeoutMs: 150 });
      await expect(p).rejects.toBeInstanceOf(VerificationTimeoutError);
      await expect(p).rejects.toMatchObject({ guid: GUID, lastStatus: expect.stringContaining('HTTP 503') });
      expect(srv.seen.length).toBeGreaterThan(2);
    } finally {
      await srv.close();
    }
  });

  it('backs off between consecutive transient errors, bounded by transientBackoffMaxMs', async () => {
    const srv = await recorder([[503, 'x'], [503, 'x'], [503, 'x'], [503, 'x'], [200, PASS]]);
    try {
      await waitForVerification(GUID, { explorerUrl: srv.url, pollIntervalMs: 20, transientBackoffMaxMs: 50, timeoutMs: 5000 });
      // seen[0] is the 503 answer to the first poll (no submission here); gaps 20, 40, 50 (capped), 50.
      const gaps = srv.seen.slice(1).map((s, i) => s.at - (srv.seen[i] as Seen).at);
      expect(gaps).toHaveLength(4);
      const want = [20, 40, 50, 50];
      gaps.forEach((g, i) => {
        expect(g).toBeGreaterThanOrEqual((want[i] as number) - 3);
        expect(g).toBeLessThan((want[i] as number) + 200);
      });
    } finally {
      await srv.close();
    }
  });

  it('marks transport failures and 5xx/429 transient, other answers not', async () => {
    const down = await recorder([[503, 'down']]);
    const limited = await recorder([[429, 'slow down']]);
    const gone = await recorder([[RESET, '']]);
    const odd = await recorder([[200, '{"verified":true}']]);
    try {
      await expect(checkVerifyStatus('g', { explorerUrl: down.url })).rejects.toMatchObject({ httpStatus: 503, transient: true });
      await expect(checkVerifyStatus('g', { explorerUrl: limited.url })).rejects.toMatchObject({ httpStatus: 429, transient: true });
      await expect(checkVerifyStatus('g', { explorerUrl: gone.url })).rejects.toMatchObject({ transient: true });
      await expect(checkVerifyStatus('g', { explorerUrl: odd.url })).rejects.toMatchObject({ httpStatus: 200, transient: false });
    } finally {
      await Promise.all([down, limited, gone, odd].map((s) => s.close()));
    }
  });

  it('bounds each explorer request with requestTimeoutMs (a hang is a transient error)', async () => {
    const hang = await recorder([[HANG, '']]);
    try {
      const t0 = Date.now();
      await expect(checkVerifyStatus('g', { explorerUrl: hang.url, requestTimeoutMs: 100 })).rejects.toMatchObject({
        name: 'ExplorerResponseError',
        transient: true,
      });
      await expect(
        verifyContract({ address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: hang.url, requestTimeoutMs: 100, wait: false }),
      ).rejects.toBeInstanceOf(ExplorerResponseError);
      expect(Date.now() - t0).toBeLessThan(3000);
    } finally {
      await hang.close();
    }
  });

  it('a status request that hangs is retried by the wait', async () => {
    const srv = await recorder([[HANG, ''], [200, PASS]]);
    try {
      const s = await waitForVerification(GUID, { explorerUrl: srv.url, requestTimeoutMs: 100, pollIntervalMs: 5, timeoutMs: 5000 });
      expect(s.state).toBe('verified');
      expect(srv.seen).toHaveLength(2);
    } finally {
      await srv.close();
    }
  });

  it('every explorer fetch carries a timeout signal (default 60 s)', async () => {
    expect(DEFAULT_EXPLORER_REQUEST_TIMEOUT_MS).toBe(60_000);
    const signals: unknown[] = [];
    const fetch: VerifyFetch = async (_url, init) => {
      signals.push(init?.signal);
      return { ok: true, status: 200, text: async () => PASS };
    };
    await checkVerifyStatus('g', { fetch });
    await verifyContract({ address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', fetch, wait: false });
    expect(signals).toHaveLength(2);
    for (const sig of signals) {
      expect(sig).toBeInstanceOf(AbortSignal);
      expect((sig as AbortSignal).aborted).toBe(false);
    }
  });

  it('already verified resolves already_verified', async () => {
    const srv = await recorder([[200, JSON.stringify({ status: '0', message: 'NOTOK', result: 'Contract source code already verified' })]]);
    try {
      const r = await verifyContract({ chainId: 40204, address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: srv.url });
      expect(r.status).toBe('already_verified');
    } finally {
      await srv.close();
    }
  });

  it('other refusals throw VerificationRejectedError with the explorer string', async () => {
    const msg = `Unable to locate ContractCode at ${FORGE_ADDR}`;
    const srv = await recorder([[200, JSON.stringify({ status: '0', message: 'NOTOK', result: msg })]]);
    try {
      const p = verifyContract({ chainId: 40204, address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: srv.url });
      await expect(p).rejects.toBeInstanceOf(VerificationRejectedError);
      await expect(p).rejects.toMatchObject({ result: msg });
    } finally {
      await srv.close();
    }
  });

  it('retries after Max rate limit reached, then gives up typed', async () => {
    const limited = JSON.stringify({ status: '0', message: 'NOTOK', result: 'Max rate limit reached' });
    const ok = await recorder([[429, limited], [200, OK_GUID]]);
    const never = await recorder([[429, limited]]);
    try {
      await expect(
        verifyContract({ chainId: 40204, address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: ok.url, wait: false, ...fast }),
      ).resolves.toMatchObject({ status: 'pending' });
      expect(ok.seen).toHaveLength(2);
      await expect(
        verifyContract({ chainId: 40204, address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: never.url, ...fast }),
      ).rejects.toBeInstanceOf(VerificationRateLimitedError);
      expect(never.seen).toHaveLength(3);
    } finally {
      await ok.close();
      await never.close();
    }
  });

  it('non-envelope answers throw ExplorerResponseError', async () => {
    const bad = await recorder([[502, 'bad gateway']]);
    const odd = await recorder([[200, '{"verified":true}']]);
    try {
      await expect(checkVerifyStatus('g', { explorerUrl: bad.url })).rejects.toMatchObject({ httpStatus: 502 });
      await expect(checkVerifyStatus('g', { explorerUrl: odd.url })).rejects.toBeInstanceOf(ExplorerResponseError);
    } finally {
      await bad.close();
      await odd.close();
    }
  });

  it('refuses a remote plaintext explorer URL and bad params before sending', async () => {
    await expect(
      verifyContract({ chainId: 40204, address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter', explorerUrl: 'http://explorer.example.com/api' }),
    ).rejects.toThrow(/http/i);
    await expect(verifyContract({ chainId: 0, address: FORGE_ADDR, buildInfo: forgeBuildInfo(), contract: 'Greeter' })).rejects.toBeInstanceOf(BuildInfoError);
    await expect(verifyContract({ chainId: 40204, address: FORGE_ADDR, contract: 'Greeter' })).rejects.toBeInstanceOf(BuildInfoError);
  });

  it('defaults to the CitrateScan API and is exported from the package root', () => {
    expect(DEFAULT_EXPLORER_URL).toBe('https://explorer.citrate.ai/api');
    expect(sdk.verifyContract).toBe(verifyContract);
    expect(sdk.deployAndVerify).toBe(deployAndVerify);
    expect(sdk.verify.loadBuildInfo).toBe(loadBuildInfo);
  });
});

// ---------------------------------------------------------------------------
// deployAndVerify
// ---------------------------------------------------------------------------

describe('deployAndVerify', () => {
  const DEPLOYED = '0x00000000000000000000000000000000000000d1';
  const TX = `0x${'ab'.repeat(32)}`;

  /** Test-only deployer that records what it was asked to send. */
  function recordingDeployer(): ContractDeployer & { sent: { data: string; value?: bigint; gasLimit?: bigint }[] } {
    const sent: { data: string; value?: bigint; gasLimit?: bigint }[] = [];
    return {
      sent,
      deployContract: async (p) => {
        sent.push(p);
        return { address: DEPLOYED, txHash: TX };
      },
    };
  }

  it('deploys build-info bytecode + ABI-encoded args, then verifies with the creation tx', async () => {
    const srv = await recorder([[200, OK_GUID], [200, PASS]]);
    try {
      const bi = forgeBuildInfo();
      const deployer = recordingDeployer();
      const r = await deployAndVerify({ client: deployer, chainId: 40204, buildInfo: bi, contract: 'Greeter', args: [7n, 'hello'], explorerUrl: srv.url, ...fast });

      const greeter = bi.output?.contracts?.['src/Greeter.sol']?.['Greeter'];
      const encoded = new ethers.Interface(greeter?.abi as ethers.InterfaceAbi).encodeDeploy([7n, 'hello']).slice(2);
      expect(deployer.sent).toEqual([{ data: `0x${greeter?.evm?.bytecode?.object}${encoded}` }]);
      expect(r).toMatchObject({ address: DEPLOYED, txHash: TX, verification: { status: 'verified', guid: GUID } });

      const body = Object.fromEntries(new URLSearchParams((srv.seen[0] as Seen).body));
      expect(body.contractaddress).toBe(DEPLOYED);
      expect(body.creationtxhash).toBe(TX);
      expect(body.constructorArguements).toBe(encoded);
      expect(body.contractname).toBe('src/Greeter.sol:Greeter');
    } finally {
      await srv.close();
    }
  });

  it('chainId is optional: omitted sends no chainid, given is sent on submit and every poll', async () => {
    const without = await recorder([[200, OK_GUID], [200, PENDING], [200, PASS]]);
    const withId = await recorder([[200, OK_GUID], [200, PENDING], [200, PASS]]);
    try {
      await deployAndVerify({ client: recordingDeployer(), buildInfo: forgeBuildInfo(), contract: 'Greeter', args: [1n, 'x'], explorerUrl: without.url, ...fast });
      expect(without.seen).toHaveLength(3);
      expect(Object.fromEntries(new URLSearchParams((without.seen[0] as Seen).body))).not.toHaveProperty('chainid');
      for (const s of without.seen.slice(1)) expect(query(s)).not.toHaveProperty('chainid');

      await deployAndVerify({ client: recordingDeployer(), chainId: 40204, buildInfo: forgeBuildInfo(), contract: 'Greeter', args: [1n, 'x'], explorerUrl: withId.url, ...fast });
      expect(withId.seen).toHaveLength(3);
      expect(Object.fromEntries(new URLSearchParams((withId.seen[0] as Seen).body)).chainid).toBe('40204');
      for (const s of withId.seen.slice(1)) expect(query(s).chainid).toBe('40204');
    } finally {
      await without.close();
      await withId.close();
    }
  });

  it('retries while the explorer has not indexed the new contract', async () => {
    const notYet = JSON.stringify({ status: '0', message: 'NOTOK', result: `Unable to locate ContractCode at ${DEPLOYED}` });
    const srv = await recorder([[200, notYet], [200, notYet], [200, OK_GUID], [200, PASS]]);
    try {
      const r = await deployAndVerify({ client: recordingDeployer(), chainId: 40204, buildInfo: forgeBuildInfo(), contract: 'Greeter', args: [1n, 'x'], explorerUrl: srv.url, ...fast });
      expect(r.verification.status).toBe('verified');
      expect(srv.seen.filter((s) => s.method === 'POST')).toHaveLength(3);
    } finally {
      await srv.close();
    }
  });

  it('waits at least the rate-limit backoff between not-indexed resubmissions', async () => {
    const notYet = JSON.stringify({ status: '0', message: 'NOTOK', result: `Unable to locate ContractCode at ${DEPLOYED}` });
    const srv = await recorder([[200, notYet], [200, notYet], [200, OK_GUID], [200, PASS]]);
    try {
      await deployAndVerify({
        client: recordingDeployer(),
        buildInfo: forgeBuildInfo(),
        contract: 'Greeter',
        args: [1n, 'x'],
        explorerUrl: srv.url,
        pollIntervalMs: 5,
        rateLimitBackoffMs: 150,
        timeoutMs: 5000,
      });
      const posts = srv.seen.filter((s) => s.method === 'POST');
      expect(posts).toHaveLength(3);
      for (let i = 1; i < posts.length; i++) {
        expect((posts[i] as Seen).at - (posts[i - 1] as Seen).at).toBeGreaterThanOrEqual(147);
      }
    } finally {
      await srv.close();
    }
  });

  it('refuses bad inputs before deploying anything', async () => {
    const deployer = recordingDeployer();
    await expect(deployAndVerify({ client: deployer, chainId: 40204, contract: 'Greeter' })).rejects.toBeInstanceOf(BuildInfoError);
    await expect(
      deployAndVerify({ client: deployer, chainId: 40204, buildInfo: forgeBuildInfo(), contract: 'Greeter', args: [1n, 'x'], constructorArgs: '0x00' }),
    ).rejects.toBeInstanceOf(BuildInfoError);
    const linked = forgeBuildInfo();
    const g = linked.output?.contracts?.['src/Greeter.sol']?.['Greeter'];
    if (g?.evm?.bytecode) g.evm.bytecode.object = `6080__$0123456789abcdef0123456789abcdef01$__`;
    await expect(deployAndVerify({ client: deployer, chainId: 40204, buildInfo: linked, contract: 'Greeter' })).rejects.toThrow(/unlinked/);
    expect(deployer.sent).toHaveLength(0);
  });

  it('CitrateClient provides deployContract and refuses without a wallet', async () => {
    const client = new sdk.CitrateClient({ rpcUrl: 'http://127.0.0.1:1', expectedGenesisHash: null });
    await expect(client.deployContract({ data: '0x6080' })).rejects.toThrow(/Wallet required/);
  });
});
