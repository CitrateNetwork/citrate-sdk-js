/**
 * Model-related type definitions
 */

export enum ModelType {
  COREML = 'coreml',
  ONNX = 'onnx',
  TENSORFLOW = 'tensorflow',
  PYTORCH = 'pytorch',
  CUSTOM = 'custom'
}

export enum AccessType {
  PUBLIC = 'public',
  PRIVATE = 'private',
  PAID = 'paid',
  WHITELIST = 'whitelist'
}

export interface ModelConfig {
  name: string;
  description?: string;
  modelType: ModelType;
  version?: string;
  accessType: AccessType;
  accessPrice: bigint; // Price in wei per inference
  accessList?: string[]; // Whitelist addresses
  encrypted: boolean;
  encryptionConfig?: EncryptionConfig;
  metadata?: Record<string, any>;
  tags?: string[];
  maxBatchSize?: number;
  timeoutSeconds?: number;
  memoryLimitMb?: number;
  revenueShares?: Record<string, number>; // address -> percentage
}

export interface EncryptionConfig {
  algorithm: string;
  keyDerivation: string;
  accessControl: boolean;
  /** Shamir threshold for splitting the model key. 0 disables key sharing. */
  thresholdShares: number;
  totalShares: number;
  /**
   * Required when `thresholdShares > 0` (PBA-L4-001): one distinct secp256k1
   * public key per share. Each share is ECDH-wrapped (V2 envelope) to its
   * holder and returned to the caller as `keyShareEnvelopes` for off-chain
   * delivery. Shares are never written to deploy metadata or calldata.
   */
  shareHolderPublicKeys?: string[];
  /**
   * `thresholdShares: 1` means any single holder recovers the key. It is
   * refused unless this is `true`.
   */
  allowSingleHolderRecovery?: boolean;
}

/**
 * One Shamir share of a model key, wrapped to a single holder (PBA-L4-001).
 * Deliver it to that holder off-chain; it is never part of deploy calldata.
 * The holder opens it with `KeyManager.unwrapKeyShare`.
 */
export interface KeyShareEnvelope {
  /** Share index (the Shamir x coordinate, 1..255). Not secret. */
  x: number;
  /** Threshold the owner chose. Not secret. */
  threshold: number;
  /** Holder public key the share is wrapped to (uncompressed hex, no 0x). */
  holderPublicKey: string;
  /** ECDH V2 envelope (`KeyManager.encryptData` format) holding the share y. */
  envelope: string;
}

export interface ModelDeployment {
  modelId: string;
  txHash: string;
  ipfsHash: string;
  encrypted: boolean;
  accessPrice: bigint;
  deploymentTime: number;
  gasUsed?: bigint;
  deploymentCost?: bigint;
  /**
   * Holder-wrapped key shares when threshold sharing was requested. Deliver
   * each to its holder off-chain; none of this is on-chain (PBA-L4-001).
   */
  keyShareEnvelopes?: KeyShareEnvelope[];
}

export interface ModelInfo {
  modelId: string;
  name: string;
  description: string;
  owner: string;
  modelType: ModelType;
  accessType: AccessType;
  accessPrice: bigint;
  encrypted: boolean;
  ipfsHash: string;
  deploymentTime: number;
  totalInferences: number;
  totalRevenue: bigint;
  metadata: Record<string, any>;
  tags: string[];
}

export interface ModelStats {
  modelId: string;
  totalInferences: number;
  totalRevenue: bigint;
  averageExecutionTime: number;
  averageGasCost: bigint;
  uniqueUsers: number;
  lastInferenceTime: number;
}

export interface ModelVersion {
  modelId: string;
  version: string;
  ipfsHash: string;
  deploymentTime: number;
  changes: string;
  deprecated: boolean;
}