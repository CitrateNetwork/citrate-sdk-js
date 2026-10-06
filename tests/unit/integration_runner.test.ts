interface IntegrationInvocation {
  command: string;
  args: string[];
  env: NodeJS.ProcessEnv;
}

interface InvocationOptions {
  testnetDefaults: boolean;
  env: NodeJS.ProcessEnv;
  extraArgs?: string[];
  nodeExecutable: string;
  jestPath: string;
}

interface IntegrationRunnerModule {
  createIntegrationInvocation(options: InvocationOptions): IntegrationInvocation;
}

const { createIntegrationInvocation } = require('../../scripts/run-integration-tests.cjs') as IntegrationRunnerModule;

describe('cross-platform integration test runner', () => {
  test('applies the documented testnet defaults without a shell', () => {
    const invocation = createIntegrationInvocation({
      testnetDefaults: true,
      env: { EXISTING: 'kept' },
      nodeExecutable: 'C:\\Program Files\\nodejs\\node.exe',
      jestPath: 'C:\\repo\\node_modules\\jest\\bin\\jest.js',
    });

    expect(invocation.command).toBe('C:\\Program Files\\nodejs\\node.exe');
    expect(invocation.env).toMatchObject({
      EXISTING: 'kept',
      CITRATE_RPC_URL: 'http://localhost:8545',
      CITRATE_CHAIN_ID: '40204',
    });
  });

  test('preserves explicit RPC and chain-ID overrides', () => {
    const invocation = createIntegrationInvocation({
      testnetDefaults: true,
      env: {
        CITRATE_RPC_URL: 'https://rpc.example.test',
        CITRATE_CHAIN_ID: '1337',
      },
      nodeExecutable: '/usr/bin/node',
      jestPath: '/repo/node_modules/jest/bin/jest.js',
    });

    expect(invocation.env.CITRATE_RPC_URL).toBe('https://rpc.example.test');
    expect(invocation.env.CITRATE_CHAIN_ID).toBe('1337');
  });

  test('does not add testnet defaults to the general integration command', () => {
    const invocation = createIntegrationInvocation({
      testnetDefaults: false,
      env: { EXISTING: 'kept' },
      nodeExecutable: '/usr/bin/node',
      jestPath: '/repo/node_modules/jest/bin/jest.js',
    });

    expect(invocation.env).toEqual({ EXISTING: 'kept' });
  });

  test('constructs stable Jest arguments and forwards caller arguments', () => {
    const invocation = createIntegrationInvocation({
      testnetDefaults: false,
      env: {},
      extraArgs: ['--listTests'],
      nodeExecutable: '/usr/bin/node',
      jestPath: '/repo/node_modules/jest/bin/jest.js',
    });

    expect(invocation.args).toEqual([
      '/repo/node_modules/jest/bin/jest.js',
      '--testMatch=**/tests/integration/**/*.test.ts',
      '--runInBand',
      '--testTimeout=120000',
      '--listTests',
    ]);
  });
});
