/**
 * Citrate JavaScript/TypeScript SDK
 *
 * A comprehensive SDK for interacting with the Citrate AI blockchain platform.
 * Provides easy-to-use interfaces for model deployment, inference execution,
 * encryption, access control, and payment systems.
 */

export { CitrateClient } from './client/CitrateClient';
export { WebSocketClient } from './client/WebSocketClient';

// Types and interfaces
export * from './types/Model';
export * from './types/Inference';
export * from './types/Crypto';
export * from './types/Transaction';
export * from './types/Client';

// Crypto utilities
export { CryptoManager } from './crypto/CryptoManager';
export { KeyManager } from './crypto/KeyManager';
export { splitSecretBytes, reconstructSecretBytes, GF256, ShamirSecretSharing } from './crypto/FiniteField';

// Error classes
export * from './errors/CitrateError';

// Utils
export * from './utils/constants';
export * from './utils/validation';

// React hooks (only if React is installed)
// Import separately: import { useCitrateClient } from '@citratenetwork/sdk/react/hooks'
// export * from './react/hooks'; // Commented out to avoid requiring React as dependency

// Version (kept in sync with package.json)
export const VERSION = '0.2.0';
// Embedded wallet (ERC-4337 v0.7 / Kernel v3) — EW-S1 WP-7
export * as aa from './aa';

// Identity authorization spine + embedded smart-account wallet (DEVX-S1).
// OIDC PKCE + SIWE, hardened ID-token verification, wallet address prediction
// (verified against the on-chain factory, never the authority), userinfo→capabilities.
export * as identity from './identity';
// Entitlement capabilities — canonical normalizeTier() + capability map (DEVX-S2, ADR-0002).
export * as entitlements from './entitlements/capabilities';
// Inference gateway — OpenAI-compatible client over infer.citrate.ai (DEVX-S2).
export * as gateway from './gateway/client';
