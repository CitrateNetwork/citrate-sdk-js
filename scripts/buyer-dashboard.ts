/**
 * A-13: Minimal Buyer CLI Dashboard
 *
 * Shows: balance, registered models, inference requests, learning cycle state.
 *
 * Run: npx ts-node scripts/buyer-dashboard.ts [--rpc URL] [--key PRIVATE_KEY]
 */

// @ts-nocheck
import { ethers } from 'ethers';

const CONTRACTS = {
  AIModelRegistryPortable: '0xa85b028984bc54a2a3d844b070544f59dddf89de',
  AIInferenceRouterPortable: '0xd499f5f7d3c918d0e553ba03954c4e02af16b6e4',
  AILearningCycleCorePortable: '0xdadd1125b8df98a66abd5eb302c0d9ca5a061dc2',
};

const REGISTRY_ABI = [
  'function modelCount() view returns (uint256)',
  'function getModelHash(bytes32 modelId) view returns (bytes32)',
  'function getModelOwner(bytes32 modelId) view returns (address)',
  'function getExecutionProfile() view returns (uint8)',
];

const ROUTER_ABI = [
  'function requestCount() view returns (uint256)',
];

const CYCLE_ABI = [
  'function cycleCount() view returns (uint256)',
  'function getCycleState(uint256 cycleId) view returns (uint8)',
  'function getCycleInfo(uint256 cycleId) view returns (uint8 state, uint256 checkpointHeight, address coordinator, uint256 participantCount, uint256 commitmentCount)',
];

async function main() {
  // Parse args
  const args = process.argv.slice(2);
  let rpcUrl = 'http://127.0.0.1:8545';
  let privateKey = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--rpc' && args[i + 1]) rpcUrl = args[++i];
    if (args[i] === '--key' && args[i + 1]) privateKey = args[++i];
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(privateKey, provider);
  const network = await provider.getNetwork();

  console.log('┌────────────────────────────────────────────────────────┐');
  console.log('│  Citrate Buyer Dashboard                              │');
  console.log('├────────────────────────────────────────────────────────┤');
  console.log(`│  Chain ID:  ${network.chainId.toString().padEnd(42)}│`);
  console.log(`│  RPC:       ${rpcUrl.padEnd(42)}│`);
  console.log(`│  Address:   ${wallet.address.padEnd(42)}│`);

  // Balance
  const balance = await provider.getBalance(wallet.address);
  const balStr = ethers.formatEther(balance);
  console.log(`│  Balance:   ${(balStr.substring(0, 12) + ' SALT').padEnd(42)}│`);
  console.log('├────────────────────────────────────────────────────────┤');

  // Block info
  const blockNumber = await provider.getBlockNumber();
  console.log(`│  Block:     #${blockNumber.toString().padEnd(41)}│`);

  // Models
  const registry = new ethers.Contract(CONTRACTS.AIModelRegistryPortable, REGISTRY_ABI, provider);
  const modelCount = await registry.modelCount();
  console.log('├────────────────────────────────────────────────────────┤');
  console.log(`│  Models Registered: ${modelCount.toString().padEnd(34)}│`);

  // Inference requests
  const router = new ethers.Contract(CONTRACTS.AIInferenceRouterPortable, ROUTER_ABI, provider);
  const requestCount = await router.requestCount();
  console.log(`│  Inference Requests: ${requestCount.toString().padEnd(33)}│`);

  // Learning cycles
  const cycle = new ethers.Contract(CONTRACTS.AILearningCycleCorePortable, CYCLE_ABI, provider);
  const cycleCount = await cycle.cycleCount();
  console.log(`│  Learning Cycles: ${cycleCount.toString().padEnd(35)}│`);

  if (cycleCount > 0n) {
    console.log('├────────────────────────────────────────────────────────┤');
    console.log('│  Recent Cycles:                                       │');
    const stateNames = ['Open', 'Collecting', 'Aggregating', 'Finalized'];
    const showCount = Math.min(Number(cycleCount), 5);
    for (let i = 0; i < showCount; i++) {
      try {
        const info = await cycle.getCycleInfo(i);
        const stateName = stateNames[Number(info.state)] || `Unknown(${info.state})`;
        const line = `  Cycle #${i}: ${stateName}, ${info.participantCount} participants, ${info.commitmentCount} commits`;
        console.log(`│${line.padEnd(55)}│`);
      } catch {
        const state = await cycle.getCycleState(i);
        const stateName = stateNames[Number(state)] || `Unknown(${state})`;
        console.log(`│  Cycle #${i}: ${stateName.padEnd(43)}│`);
      }
    }
  }

  // Execution profile
  const profile = await registry.getExecutionProfile();
  console.log('├────────────────────────────────────────────────────────┤');
  console.log(`│  Execution Profile: ${(profile === 0n ? 'PortableWasm (L0)' : 'NativePrecompile').padEnd(34)}│`);
  console.log('└────────────────────────────────────────────────────────┘');
}

main().catch((err) => {
  console.error('Dashboard error:', err.message);
  process.exit(1);
});
