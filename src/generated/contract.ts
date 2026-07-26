/**
 * federation-contract.ts — typed accessor over the vendored federation contract
 * artifact (DEVX-S0, ADR-0001). This is the single source of truth for chain
 * addresses, chainId, endpoints, and the entitlement tier vocabulary.
 *
 * Do NOT hand-edit `federation-contract.json`. It is synced from
 * `citrate-federation/contract/federation-contract.json` via `npm run sync-contract`,
 * which is itself generated from `citrate-chain/contracts/addresses/40204.json` +
 * `citrate-identity/src/entitlements.ts`. CI runs `npm run verify:contract`.
 */
import raw from './federation-contract.json';

/** 0x-prefixed hex string (matches the SDK/ethers address & data convention). */
export type Hex = `0x${string}`;

export interface FederationContract {
  schemaVersion: number;
  chain: { chainId: number; chainName: string; rpcUrl: string; explorerUrl: string; wsUrl: string };
  contracts: Record<string, Hex>;
  aaStack: {
    EntryPoint: Hex;
    CitrateWallet: Hex;
    CitrateWalletFactory: Hex;
    CitratePaymaster: Hex;
    WebAuthnP256Validator: Hex;
    CitrateECDSAValidator: Hex;
    GuardianRecoveryModule: Hex;
  };
  membership: { CitrateMemberSBT: Hex | null; MembershipStakeVault: Hex | null };
  precompiles: Record<string, Hex>;
  identity: { issuer: string; discovery: string; jwks: string; scopes: string[]; entitlementClaim: string };
  entitlements: { tiers: string[]; kycBaselineTier: string };
  gateway: { baseUrl: string; keyPrefix: string };
  provenance: { deployer: string | null; deployedAt: string | null; sourceHashes: Record<string, string> };
}

export const FEDERATION_CONTRACT: FederationContract = raw as unknown as FederationContract;

/** The federation entitlement tier vocabulary (5 values; see ADR-0002). */
export type EntitlementTier = 'public' | 'commercial' | 'commercial.kyc' | 'academic' | 'confidential';
