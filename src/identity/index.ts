/**
 * @citratenetwork/identity (DEVX-S1) — the Citrate authorization spine + embedded wallet.
 * Currently ships inside citrate-js; DEVX-S3 extracts it to its own package (ADR-0003).
 */
export * from './wallet';
export * from './pkce';
export * from './jwt';
export * from './client';
export * from '../entitlements/capabilities';
