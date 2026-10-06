'use strict';

const { spawnSync } = require('node:child_process');

const TESTNET_DEFAULTS_FLAG = '--testnet-defaults';
const JEST_ARGS = [
  '--testMatch=**/tests/integration/**/*.test.ts',
  '--runInBand',
  '--testTimeout=120000',
];

function createIntegrationInvocation({
  testnetDefaults = false,
  env = process.env,
  extraArgs = [],
  nodeExecutable = process.execPath,
  jestPath = require.resolve('jest/bin/jest'),
} = {}) {
  const childEnv = { ...env };
  if (testnetDefaults) {
    childEnv.CITRATE_RPC_URL ??= 'http://localhost:8545';
    childEnv.CITRATE_CHAIN_ID ??= '40204';
  }

  return {
    command: nodeExecutable,
    args: [jestPath, ...JEST_ARGS, ...extraArgs],
    env: childEnv,
  };
}

function runIntegrationTests(argv = process.argv.slice(2)) {
  const testnetDefaults = argv[0] === TESTNET_DEFAULTS_FLAG;
  const extraArgs = testnetDefaults ? argv.slice(1) : argv;
  const invocation = createIntegrationInvocation({ testnetDefaults, extraArgs });
  const result = spawnSync(invocation.command, invocation.args, {
    env: invocation.env,
    stdio: 'inherit',
  });

  if (result.error) {
    throw result.error;
  }
  return result.status ?? 1;
}

module.exports = { createIntegrationInvocation, runIntegrationTests };

if (require.main === module) {
  process.exitCode = runIntegrationTests();
}
