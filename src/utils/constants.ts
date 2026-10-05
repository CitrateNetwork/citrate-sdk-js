/**
 * Constants for Citrate JavaScript SDK
 *
 * Chain-varying values (RPC/WS endpoints, AA-stack / membership / contract
 * addresses) are DERIVED from the vendored federation contract artifact
 * (DEVX-S0, ADR-0001) — the single source of truth generated from
 * citrate-chain/contracts/addresses/40204.json. Do not hand-copy addresses here;
 * add them to the artifact and re-sync (`npm run sync-contract`).
 */
import { FEDERATION_CONTRACT } from '../generated/contract';
import {
  CHAIN_PRECOMPILES,
  CHAIN_PRECOMPILE_ADDRESSES,
  CHAIN_PRECOMPILE_SOURCE,
} from '../generated/precompiles.40204';

// Single source of truth for the package version. `index.ts` re-exports this as
// `VERSION` and the HTTP User-Agent is derived from it (SJS-B-H03: the axios UA
// was hardcoded `citrate-js-sdk/0.1.0` while the package shipped 0.2.0, so
// server-side telemetry attributed traffic to a version that had not shipped for
// two releases). Keep in lockstep with package.json `version`.
export const SDK_VERSION = '0.2.4';

// Network constants — chainId 40204 is permanent (PR #8396); the literal is
// kept for type-narrowing, and guarded to equal the artifact below.
// PBA-L8-016: the old `MAINNET: 1` entry was Ethereum mainnet's chain id, not a
// Citrate network. Removed; there is no separate Citrate mainnet chain id.
export const CHAIN_IDS = {
  TESTNET: 40204,   // Testnet beta (rpc.citrate.ai)
} as const;

/* istanbul ignore next — build-time invariant */
if (FEDERATION_CONTRACT.chain.chainId !== CHAIN_IDS.TESTNET) {
  throw new Error(
    `constants.ts: artifact chainId ${FEDERATION_CONTRACT.chain.chainId} != CHAIN_IDS.TESTNET ${CHAIN_IDS.TESTNET}`,
  );
}

// RM-G2.6 / audit SDK-02: array shape so callers can pass the full list straight
// to `CitrateClientConfig.rpcUrl` for multi-RPC fallback. Sourced from the artifact.
export const DEFAULT_RPC_URLS: Record<number, string[]> = {
  [CHAIN_IDS.TESTNET]: [FEDERATION_CONTRACT.chain.rpcUrl],
};

export const DEFAULT_WS_URLS: Record<number, string> = {
  [CHAIN_IDS.TESTNET]: FEDERATION_CONTRACT.chain.wsUrl,
};

// Account-abstraction stack addresses (ERC-4337) — sourced from the artifact so
// they can never go stale against a reroll (the June-8 EntryPoint bug class).
export const AA_ADDRESSES = FEDERATION_CONTRACT.aaStack;

// Membership contracts (CitrateMemberSBT / MembershipStakeVault) — from the artifact.
export const MEMBERSHIP_ADDRESSES = FEDERATION_CONTRACT.membership;

// Named application contracts (ModelRegistry, ComputePool, …) — from the artifact.
export const CONTRACT_ADDRESSES = FEDERATION_CONTRACT.contracts;

// Precompile table carried in the federation artifact (book names, e.g. `InferenceProofVerify`).
// It mirrors the `precompiles` block of citrate-chain's 40204.json, which does not list every
// bridged precompile; PRECOMPILE_ADDRESSES below is the complete set.
export const PRECOMPILES = FEDERATION_CONTRACT.precompiles;

// Every chain precompile, generated from citrate-chain by `npm run sync-precompiles`
// (core/execution/src/precompiles/mod.rs PURE_PRECOMPILE_ADDRESSES + AGENT_FORK_PRECOMPILE_ADDRESSES,
// plus the 40204.json `precompiles` block for the hosted inference family). Each entry carries its
// group ('hosted' | 'pure' | 'agent'), whether it is bridged into the EVM, and whether it is active
// from genesis. `npm run verify:precompiles` fails if this drifts from the chain.
export { CHAIN_PRECOMPILES, CHAIN_PRECOMPILE_SOURCE };
export type { ChainPrecompile, PrecompileGroup } from '../generated/precompiles.40204';

// Precompile addresses by key. Generated keys (e.g. INFERENCE_PROOF_VERIFY, LORA_APPLY, AGENT_OPS)
// come straight from CHAIN_PRECOMPILE_ADDRESSES; the keys spelled out below predate the generator
// and are kept so existing callers keep working.
export const PRECOMPILE_ADDRESSES = {
  ...CHAIN_PRECOMPILE_ADDRESSES,
  // Node state precompiles dispatched by executor.rs (model / artifact / governance). They sit
  // outside the EVM-bridged arrays and the book's precompiles block, so they are kept by hand.
  MODEL: '0x0000000000000000000000000000000000001000',
  ARTIFACT: '0x0000000000000000000000000000000000001002',
  GOVERNANCE: '0x0000000000000000000000000000000000001003',
  // Hosted AI inference family (0x0100-0x0106), legacy names for the generated MODEL_* keys.
  INFERENCE_DEPLOY: CHAIN_PRECOMPILE_ADDRESSES.MODEL_DEPLOY,
  INFERENCE_RUN: CHAIN_PRECOMPILE_ADDRESSES.MODEL_INFERENCE,
  INFERENCE_BATCH: CHAIN_PRECOMPILE_ADDRESSES.BATCH_INFERENCE,
  INFERENCE_METADATA: CHAIN_PRECOMPILE_ADDRESSES.MODEL_METADATA,
  INFERENCE_BENCHMARK: CHAIN_PRECOMPILE_ADDRESSES.MODEL_BENCHMARK,
  INFERENCE_ENCRYPT: CHAIN_PRECOMPILE_ADDRESSES.MODEL_ENCRYPTION,
  /**
   * @deprecated 0x0104 is the retired proof-verification address; the chain always rejects
   * calls to it. Use INFERENCE_PROOF_VERIFY (0x0108).
   */
  INFERENCE_VERIFY: '0x0000000000000000000000000000000000000104',
} as const;

// Gas limits
export const GAS_LIMITS = {
  MODEL_DEPLOY: 500000n,
  INFERENCE: 1000000n,
  ACCESS_PURCHASE: 200000n,
  METADATA_UPDATE: 100000n,
  REGISTRY_UPDATE: 150000n
} as const;

// Timeout values (milliseconds)
export const TIMEOUTS = {
  DEFAULT_REQUEST: 30000,
  MODEL_DEPLOYMENT: 300000, // 5 minutes
  INFERENCE_EXECUTION: 120000, // 2 minutes
  WEBSOCKET_CONNECTION: 10000,
  IPFS_UPLOAD: 60000
} as const;

// Model constraints
export const MODEL_LIMITS = {
  MAX_MODEL_SIZE: 100 * 1024 * 1024, // 100MB
  MAX_BATCH_SIZE: 100,
  MAX_INPUT_SIZE: 10 * 1024 * 1024, // 10MB
  MAX_OUTPUT_SIZE: 10 * 1024 * 1024, // 10MB
  MAX_METADATA_SIZE: 64 * 1024, // 64KB
  MAX_DESCRIPTION_LENGTH: 1000,
  MAX_NAME_LENGTH: 100,
  MAX_TAGS: 10,
  MAX_TAG_LENGTH: 20
} as const;

// Encryption settings.
//
// Leg-A HYG-DRIFT (SEC audit 2026-09-02): these exported constants contradicted
// the live code — PBKDF2_ITERATIONS advertised 10,000 while CryptoManager uses
// PBKDF2_DEFAULT_ITERATIONS = 600,000 (OWASP floor). Reconciled below. The ECDH
// key-encryption key is now HKDF-SHA256 (SJS-B-009), and the owner-wrap KEK is
// PBKDF2-SHA256 — both are recorded so a consumer reading these is not misled.
export const ENCRYPTION = {
  ALGORITHM: 'AES-256-GCM',
  /** ECDH key-encryption-key derivation (KeyManager.deriveSharedKey). */
  KEY_DERIVATION: 'HKDF-SHA256',
  /** Owner-wrap KEK derivation (KeyManager.encryptKeyForOwner). */
  OWNER_WRAP_KDF: 'PBKDF2-SHA256',
  NONCE_SIZE: 12,
  AUTH_TAG_SIZE: 16,
  KEY_SIZE: 32,
  SALT_SIZE: 16,
  PBKDF2_ITERATIONS: 600_000
} as const;

// Event names
export const EVENTS = {
  // Connection events
  CONNECTED: 'connected',
  DISCONNECTED: 'disconnected',
  ERROR: 'error',

  // Model events
  MODEL_DEPLOYED: 'modelDeployed',
  MODEL_UPDATED: 'modelUpdated',
  MODEL_DELETED: 'modelDeleted',

  // Inference events
  INFERENCE_STARTED: 'inferenceStarted',
  INFERENCE_PARTIAL: 'inferencePartial',
  INFERENCE_COMPLETED: 'inferenceCompleted',
  INFERENCE_FAILED: 'inferenceFailed',

  // Marketplace events
  MARKETPLACE_SALE: 'marketplaceSale',
  MARKETPLACE_LISTING: 'marketplaceListing',
  ACCESS_GRANTED: 'accessGranted',

  // Payment events
  PAYMENT_RECEIVED: 'paymentReceived',
  REVENUE_DISTRIBUTED: 'revenueDistributed'
} as const;

// Model types mapping
export const MODEL_TYPE_EXTENSIONS = {
  'coreml': ['.mlpackage', '.mlmodel'],
  'onnx': ['.onnx'],
  'tensorflow': ['.pb', '.savedmodel'],
  'pytorch': ['.pt', '.pth', '.pkl'],
  'custom': ['.json', '.bin', '.dat']
} as const;

// HTTP status codes
export const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  INTERNAL_SERVER_ERROR: 500,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503
} as const;

// WebSocket close codes
export const WS_CLOSE_CODES = {
  NORMAL_CLOSURE: 1000,
  GOING_AWAY: 1001,
  PROTOCOL_ERROR: 1002,
  UNSUPPORTED_DATA: 1003,
  INVALID_FRAME_PAYLOAD_DATA: 1007,
  POLICY_VIOLATION: 1008,
  MESSAGE_TOO_BIG: 1009,
  INTERNAL_ERROR: 1011
} as const;

// API endpoints
export const API_ENDPOINTS = {
  MODELS: '/v1/models',
  INFERENCE: '/v1/inference',
  MARKETPLACE: '/v1/marketplace',
  CHAT_COMPLETIONS: '/v1/chat/completions',
  EMBEDDINGS: '/v1/embeddings',
  JOBS: '/v1/jobs',
  MESSAGES: '/v1/messages'
} as const;