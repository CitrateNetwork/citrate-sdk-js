'use strict';

const LOCAL_DEVNET_CHAIN_ID = 1337;

class ConfigurationError extends Error {}

function parseExpectedChainId(value) {
  if (!value || !/^[1-9]\d*$/.test(value)) {
    throw new ConfigurationError('CITRATE_CHAIN_ID must be a positive decimal integer.');
  }

  const chainId = Number(value);
  if (!Number.isSafeInteger(chainId)) {
    throw new ConfigurationError('CITRATE_CHAIN_ID exceeds JavaScript safe-integer range.');
  }
  return chainId;
}

function parseRpcUrl(value) {
  if (!value) {
    throw new ConfigurationError('CITRATE_RPC_URL is required.');
  }

  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigurationError('CITRATE_RPC_URL must be a valid HTTP or HTTPS URL.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new ConfigurationError('CITRATE_RPC_URL must be a valid HTTP or HTTPS URL.');
  }
  return url.toString();
}

function createReadOnlyContext(rpcUrl) {
  const { CitrateClient, CHAIN_IDS } = require('@citratelabs/sdk');
  return {
    client: new CitrateClient({ rpcUrl }),
    publicChainId: CHAIN_IDS.TESTNET,
  };
}

async function runReadOnlyQuickstart({
  env = process.env,
  stdout = console.log,
  stderr = console.error,
  contextFactory = createReadOnlyContext,
} = {}) {
  try {
    const rpcUrl = parseRpcUrl(env.CITRATE_RPC_URL);
    const expectedChainId = parseExpectedChainId(env.CITRATE_CHAIN_ID);
    const { client, publicChainId } = await contextFactory(rpcUrl);
    const observedChainId = await client.getChainId();
    const supportedNetworks = new Map([
      [LOCAL_DEVNET_CHAIN_ID, 'local-devnet'],
      [publicChainId, 'citrate-public'],
    ]);
    const network = supportedNetworks.get(observedChainId);

    if (!network) {
      throw new ConfigurationError(
        `RPC reported unsupported chain ID ${observedChainId}; expected 1337 or ${publicChainId}.`,
      );
    }
    if (observedChainId !== expectedChainId) {
      throw new ConfigurationError(
        `Chain-ID mismatch: configured ${expectedChainId}, RPC reported ${observedChainId}.`,
      );
    }

    stdout(`Connected: network=${network} chainId=${observedChainId} mode=read-only`);
    return 0;
  } catch (error) {
    if (error instanceof ConfigurationError) {
      stderr(`Configuration error: ${error.message}`);
    } else {
      stderr('Connection error: unable to read eth_chainId from the configured RPC endpoint.');
    }
    return 1;
  }
}

module.exports = { runReadOnlyQuickstart };

if (require.main === module) {
  runReadOnlyQuickstart().then((exitCode) => {
    process.exitCode = exitCode;
  });
}
