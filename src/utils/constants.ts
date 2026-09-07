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

// Single source of truth for the package version. `index.ts` re-exports this as
// `VERSION` and the HTTP User-Agent is derived from it (SJS-B-H03: the axios UA
// was hardcoded `citrate-js-sdk/0.1.0` while the package shipped 0.2.0, so
// server-side telemetry attributed traffic to a version that had not shipped for
// two releases). Keep in lockstep with package.json `version`.
export const SDK_VERSION = '0.2.0';

// Network constants — chainId 40204 is permanent (PR #8396); the literal is
// kept for type-narrowing, and guarded to equal the artifact below.
export const CHAIN_IDS = {
  MAINNET: 1,       // Reserved for mainnet
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

// Canonical precompile table, sourced from the federation artifact (the authoritative set).
// Prefer this over the legacy PRECOMPILE_ADDRESSES below. The legacy map predates the artifact
// and carries entries the canonical table does NOT contain — notably INFERENCE_VERIFY (0x…0104),
// which is absent on-chain (the canonical proof-verify precompile is InferenceProofVerify 0x…0108),
// and the 0x1000-range state precompiles. See tests/unit/precompile_reconciliation.test.ts for the
// exact reconciliation; correcting the legacy map is a chain-team-gated change (DEVX-S3).
export const PRECOMPILES = FEDERATION_CONTRACT.precompiles;

// State-changing precompile addresses (canonical — match executor.rs)
// These are the addresses the executor actually dispatches to for on-chain model state
export const PRECOMPILE_ADDRESSES = {
  // Canonical state precompiles (executor.rs model_precompile_address / artifact / governance)
  MODEL: '0x0000000000000000000000000000000000001000',
  ARTIFACT: '0x0000000000000000000000000000000000001002',
  GOVERNANCE: '0x0000000000000000000000000000000000001003',
  // Runtime AI inference precompiles (inference.rs, 0x0100-0x0106)
  INFERENCE_DEPLOY: '0x0000000000000000000000000000000000000100',
  INFERENCE_RUN: '0x0000000000000000000000000000000000000101',
  INFERENCE_BATCH: '0x0000000000000000000000000000000000000102',
  INFERENCE_METADATA: '0x0000000000000000000000000000000000000103',
  INFERENCE_VERIFY: '0x0000000000000000000000000000000000000104',
  INFERENCE_BENCHMARK: '0x0000000000000000000000000000000000000105',
  INFERENCE_ENCRYPT: '0x0000000000000000000000000000000000000106',
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