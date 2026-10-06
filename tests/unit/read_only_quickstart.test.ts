import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { CHAIN_IDS, CitrateClient } from '../../src';

interface QuickstartOptions {
  env: NodeJS.ProcessEnv;
  stdout: (message: string) => void;
  stderr: (message: string) => void;
  contextFactory: (rpcUrl: string) => {
    client: CitrateClient;
    publicChainId: number;
  };
}

interface QuickstartModule {
  runReadOnlyQuickstart(options: QuickstartOptions): Promise<number>;
}

interface RpcRequest {
  id: unknown;
  method: unknown;
}

const quickstart = require('../../examples/read-only.cjs') as QuickstartModule;

async function startRpcServer(
  chainIdResult: string,
): Promise<{ server: Server; rpcUrl: string }> {
  const server = createServer((request, response) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk: string) => {
      body += chunk;
    });
    request.on('end', () => {
      const parsed = JSON.parse(body) as RpcRequest | RpcRequest[];
      const requests = Array.isArray(parsed) ? parsed : [parsed];
      const replies = requests.map((entry) =>
        entry.method === 'eth_chainId'
          ? { jsonrpc: '2.0', id: entry.id, result: chainIdResult }
          : {
              jsonrpc: '2.0',
              id: entry.id,
              error: { code: -32601, message: 'Method not found' },
            },
      );

      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(Array.isArray(parsed) ? replies : replies[0]));
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address() as AddressInfo;
  return { server, rpcUrl: `http://127.0.0.1:${address.port}` };
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

describe('read-only Tech Week quickstart', () => {
  async function run(chainIdResult: string, expectedChainId: string) {
    const { server, rpcUrl } = await startRpcServer(chainIdResult);
    const output: string[] = [];
    const errors: string[] = [];
    try {
      const exitCode = await quickstart.runReadOnlyQuickstart({
        env: {
          CITRATE_RPC_URL: rpcUrl,
          CITRATE_CHAIN_ID: expectedChainId,
          CITRATE_PRIVATE_KEY: 'this-value-must-not-be-read',
        },
        stdout: (message) => output.push(message),
        stderr: (message) => errors.push(message),
        contextFactory: (url) => ({
          client: new CitrateClient({ rpcUrl: url }),
          publicChainId: CHAIN_IDS.TESTNET,
        }),
      });
      return { exitCode, output, errors };
    } finally {
      await closeServer(server);
    }
  }

  test('labels local devnet 1337 and remains read-only', async () => {
    const result = await run('0x539', '1337');
    expect(result).toEqual({
      exitCode: 0,
      output: ['Connected: network=local-devnet chainId=1337 mode=read-only'],
      errors: [],
    });
  });

  test('labels public Citrate chain 40204 and remains read-only', async () => {
    const result = await run('0x9d0c', '40204');
    expect(result).toEqual({
      exitCode: 0,
      output: ['Connected: network=citrate-public chainId=40204 mode=read-only'],
      errors: [],
    });
  });

  test('refuses a configured and observed chain-ID mismatch', async () => {
    const result = await run('0x539', '40204');
    expect(result.exitCode).toBe(1);
    expect(result.output).toEqual([]);
    expect(result.errors).toEqual([
      'Configuration error: Chain-ID mismatch: configured 40204, RPC reported 1337.',
    ]);
  });

  test('refuses an unsupported observed chain', async () => {
    const result = await run('0x1', '1');
    expect(result.exitCode).toBe(1);
    expect(result.errors).toEqual([
      'Configuration error: RPC reported unsupported chain ID 1; expected 1337 or 40204.',
    ]);
  });

  test.each(['', '0x539', '-1', '1.5', '9007199254740992'])(
    'refuses malformed configured chain ID %p',
    async (chainId) => {
      const result = await run('0x539', chainId);
      expect(result.exitCode).toBe(1);
      expect(result.output).toEqual([]);
      expect(result.errors[0]).toMatch(/^Configuration error: CITRATE_CHAIN_ID/);
    },
  );

  test('reports a safe connection error for a malformed RPC chain ID', async () => {
    const result = await run('not-a-chain-id', '1337');
    expect(result.exitCode).toBe(1);
    expect(result.output).toEqual([]);
    expect(result.errors).toEqual([
      'Connection error: unable to read eth_chainId from the configured RPC endpoint.',
    ]);
  });
});
