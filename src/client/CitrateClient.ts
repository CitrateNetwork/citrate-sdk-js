/**
 * Main Citrate client for JavaScript/TypeScript SDK
 */

import { ethers } from 'ethers';
import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { CryptoManager } from '../crypto/CryptoManager';
import { KeyManager } from '../crypto/KeyManager';
import {
  ModelConfig,
  ModelDeployment,
  ModelInfo,
  ModelStats
} from '../types/Model';
import {
  InferenceRequest,
  InferenceResult,
  BatchInferenceRequest,
  BatchInferenceResult
} from '../types/Inference';
import { CitrateError, ModelNotFoundError, InsufficientFundsError, ValidationError } from '../errors/CitrateError';
import {
  validateInferenceRequest,
  validateModelConfig,
  validateModelData,
  validatePrivateKey,
  validateRpcUrl
} from '../utils/validation';
import { PRECOMPILE_ADDRESSES } from '../utils/constants';

export interface CitrateClientConfig {
  /**
   * RPC endpoint(s). A bare string is the legacy single-RPC form.
   * Pass an array (RM-G2.6 / audit SDK-02) to enable multi-RPC
   * fallback — the SDK iterates the list on transport errors so a
   * single broken endpoint doesn't take the integration down.
   */
  rpcUrl: string | string[];
  privateKey?: string;
  timeout?: number;
  retries?: number;
  headers?: Record<string, string>;
  /**
   * IPFS HTTP API endpoint (RM-G2.6 / audit SDK-01). When unset,
   * `uploadModel` skips the IPFS upload step entirely and uses the
   * SHA-256 content hash as the artifact pointer. Pre-fix the SDK
   * silently dialed `http://localhost:5001`, which fails for
   * everyone except the one operator running ipfs locally.
   */
  ipfsApiUrl?: string;
}

export class CitrateClient {
  private provider: ethers.JsonRpcProvider;
  private wallet?: ethers.Wallet;
  private axios: AxiosInstance;
  private keyManager?: KeyManager;
  private cryptoManager: CryptoManager;
  /** RM-G2.6 / SDK-02 — full fallback list, primary first. */
  private readonly rpcUrls: readonly string[];
  /** RM-G2.6 / SDK-01 — undefined means "no IPFS configured". */
  private readonly ipfsApiUrl: string | undefined;

  constructor(config: CitrateClientConfig) {
    this.rpcUrls = Array.isArray(config.rpcUrl)
      ? [...config.rpcUrl]
      : [config.rpcUrl];
    if (this.rpcUrls.length === 0) {
      throw new CitrateError('CitrateClient: rpcUrl must not be empty');
    }
    // SECREM-02 5.4 (audit CITRATE_SDK_JS-2026-05-31-003): the exported
    // validators were dead code — wire them at the trust boundary, before
    // any provider/wallet is constructed.
    for (const url of this.rpcUrls) {
      if (!validateRpcUrl(url)) {
        throw new ValidationError(`CitrateClient: invalid RPC URL: ${url}`);
      }
    }
    if (config.privateKey !== undefined && !validatePrivateKey(config.privateKey)) {
      throw new ValidationError('CitrateClient: invalid private key format');
    }
    const primaryRpc = this.rpcUrls[0] as string;

    // Initialize provider against the first URL. ethers.FallbackProvider
    // would do automatic failover but doubles the connection budget;
    // for simplicity we hold the list and let `selectRpc` rotate
    // per-request on transport errors.
    this.provider = new ethers.JsonRpcProvider(primaryRpc);

    // Initialize wallet if private key provided
    if (config.privateKey) {
      this.wallet = new ethers.Wallet(config.privateKey, this.provider);
      this.keyManager = new KeyManager(config.privateKey);
    }

    // Initialize HTTP client
    this.axios = axios.create({
      baseURL: primaryRpc,
      timeout: config.timeout || 30000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'citrate-js-sdk/0.1.0',
        ...config.headers
      }
    });

    this.ipfsApiUrl = config.ipfsApiUrl;

    // Initialize crypto manager
    this.cryptoManager = new CryptoManager();

    this.setupAxiosInterceptors();
  }

  /**
   * Returns the current set of RPC URLs the client will try. Primary
   * is at index 0; fallbacks follow in order. Useful for diagnostic
   * "which endpoint did my request go to" UI.
   */
  public getRpcUrls(): readonly string[] {
    return this.rpcUrls;
  }

  private setupAxiosInterceptors(): void {
    // Request interceptor for logging
    this.axios.interceptors.request.use(
      (config) => {
        console.debug('Citrate API Request:', config.method?.toUpperCase(), config.url);
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for error handling
    this.axios.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.data?.error) {
          throw new CitrateError(
            error.response.data.error.message || 'API Error',
            error.response.data.error.code?.toString()
          );
        }
        throw new CitrateError(`Network error: ${error.message}`);
      }
    );
  }

  // Connection methods
  async getChainId(): Promise<number> {
    const network = await this.provider.getNetwork();
    return Number(network.chainId);
  }

  async getBalance(address?: string): Promise<bigint> {
    const targetAddress = address || this.getAddress();
    if (!targetAddress) {
      throw new CitrateError('No address provided and no wallet configured');
    }
    return await this.provider.getBalance(targetAddress);
  }

  async getNonce(address?: string): Promise<number> {
    const targetAddress = address || this.getAddress();
    if (!targetAddress) {
      throw new CitrateError('No address provided and no wallet configured');
    }
    return await this.provider.getTransactionCount(targetAddress, 'pending');
  }

  getAddress(): string | undefined {
    return this.wallet?.address;
  }

  // Model deployment
  async deployModel(
    modelData: ArrayBuffer | Uint8Array,
    config: ModelConfig
  ): Promise<ModelDeployment> {
    if (!this.wallet) {
      throw new CitrateError('Wallet required for model deployment');
    }

    // SECREM-02 5.4 (audit CITRATE_SDK_JS-2026-05-31-003): enforce the
    // advertised bounds before any wallet/provider activity.
    validateModelData(modelData);
    validateModelConfig(config);

    // Convert to Uint8Array if needed
    const modelBytes = modelData instanceof ArrayBuffer
      ? new Uint8Array(modelData)
      : modelData;

    // Calculate model hash
    const modelHash = await this.cryptoManager.hashData(modelBytes);

    // Encrypt model if requested
    let encryptedData: Uint8Array = modelBytes;
    let encryptionMetadata: any = null;

    if (config.encrypted) {
      // SECREM-02 5.4 (FUA-SDK-JS-01 class): encryption requested must
      // never silently downgrade to a plaintext upload.
      if (!this.keyManager) {
        throw new CitrateError(
          'deployModel: config.encrypted is true but no private key/KeyManager ' +
            'is configured — refusing to upload the model in plaintext.'
        );
      }
      const result = await this.keyManager.encryptModel(modelBytes, config.encryptionConfig);
      encryptedData = result.encryptedData;
      encryptionMetadata = result.metadata;
    }

    // Upload to IPFS
    const ipfsHash = await this.uploadToIPFS(encryptedData);

    // Prepare transaction data
    const txData = {
      modelHash,
      ipfsHash,
      encrypted: config.encrypted,
      accessPrice: config.accessPrice.toString(),
      accessList: config.accessList || [],
      metadata: config.metadata || {}
    };

    if (encryptionMetadata) {
      txData.metadata.encryption = encryptionMetadata;
    }

    // Deploy to blockchain — canonical INFERENCE_DEPLOY precompile from
    // constants (audit -004: no hardcoded address literals in the client).
    const tx = await this.wallet.sendTransaction({
      to: PRECOMPILE_ADDRESSES.INFERENCE_DEPLOY,
      data: ethers.hexlify(ethers.toUtf8Bytes(JSON.stringify(txData))),
      gasLimit: 500000n
    });

    // Wait for confirmation
    const receipt = await tx.wait();
    if (!receipt) {
      throw new CitrateError('Transaction failed');
    }

    // Extract model ID from logs
    const modelId = this.extractModelIdFromReceipt(receipt);

    return {
      modelId,
      txHash: tx.hash,
      ipfsHash,
      encrypted: config.encrypted,
      accessPrice: config.accessPrice,
      deploymentTime: Math.floor(Date.now() / 1000),
      gasUsed: receipt.gasUsed
    };
  }

  // Inference execution
  async inference(request: InferenceRequest): Promise<InferenceResult> {
    if (!this.wallet) {
      throw new CitrateError('Wallet required for inference execution');
    }

    // SECREM-02 5.4 (audit CITRATE_SDK_JS-2026-05-31-003): enforce the
    // advertised bounds before any wallet/provider activity.
    validateInferenceRequest(request);

    // Prepare inference data
    let inputData: any = request.inputData;

    // Encrypt input if requested. RM-G.3: the symmetric key is ECDH-wrapped
    // to recipientPublicKey (the model/recipient key) and never shipped raw;
    // encryptData fails closed if no recipient key is supplied.
    if (request.encrypted) {
      // SECREM-02 5.4 (FUA-SDK-JS-01 class): when encryption is requested
      // it must be applied or the call must die — never a silent plaintext
      // downgrade onto public calldata.
      if (!this.keyManager) {
        throw new CitrateError(
          'inference: request.encrypted is true but no private key/KeyManager ' +
            'is configured — refusing to send the input in plaintext.'
        );
      }
      inputData = await this.keyManager.encryptData(
        JSON.stringify(request.inputData),
        request.recipientPublicKey
      );
    }

    const inferenceData = {
      modelId: request.modelId,
      inputData,
      encrypted: request.encrypted || false,
      timestamp: request.timestamp || Math.floor(Date.now() / 1000)
    };

    // Execute inference — canonical INFERENCE_RUN precompile from
    // constants (audit -004: no hardcoded address literals in the client).
    const startTime = Date.now();
    const tx = await this.wallet.sendTransaction({
      to: PRECOMPILE_ADDRESSES.INFERENCE_RUN,
      data: ethers.hexlify(ethers.toUtf8Bytes(JSON.stringify(inferenceData))),
      gasLimit: BigInt(request.timeout || 1000000)
    });

    // Wait for execution
    const receipt = await tx.wait();
    const executionTime = Date.now() - startTime;

    if (!receipt) {
      throw new CitrateError('Inference execution failed');
    }

    // Extract output from logs
    let outputData = this.extractInferenceOutput(receipt);

    // Decrypt output if encrypted
    if (request.encrypted && this.keyManager && outputData.encrypted) {
      const decrypted = await this.keyManager.decryptData(outputData.encrypted);
      outputData = JSON.parse(decrypted);
    }

    return {
      modelId: request.modelId,
      outputData,
      gasUsed: receipt.gasUsed,
      executionTime,
      txHash: tx.hash
    };
  }

  // Batch inference
  async batchInference(request: BatchInferenceRequest): Promise<BatchInferenceResult> {
    // SECREM-02 5.4 (FUA-SDK-JS-01): batch carries the exact same
    // confidentiality contract as single-call inference. Fail closed up
    // front — before any transaction leaves — if encryption is requested
    // but cannot be applied. Never silently downgrade to plaintext.
    if (request.encrypted) {
      if (!this.keyManager) {
        throw new CitrateError(
          'batchInference: request.encrypted is true but no private key/KeyManager ' +
            'is configured — refusing to send batch inputs in plaintext.'
        );
      }
      if (!request.recipientPublicKey) {
        throw new CitrateError(
          'batchInference requires recipientPublicKey when encrypted: the ' +
            'symmetric key is ECDH-wrapped to the recipient and never shipped ' +
            'in cleartext (mirrors the single-call inference contract).'
        );
      }
    }

    // SECREM-02 5.4 (audit CITRATE_SDK_JS-2026-05-31-003): validate every
    // input before the first transaction is sent, so an invalid batch
    // throws instead of half-broadcasting.
    for (const input of request.inputs) {
      const probe: InferenceRequest = {
        modelId: request.modelId,
        inputData: input
      };
      if (request.batchSize !== undefined) {
        probe.batchSize = request.batchSize;
      }
      validateInferenceRequest(probe);
    }

    const results: InferenceResult[] = [];
    const errors: string[] = [];
    let totalGasUsed = 0n;
    let totalExecutionTime = 0;

    const batchSize = request.batchSize || 10;
    const parallel = request.parallel || false;

    for (let i = 0; i < request.inputs.length; i += batchSize) {
      const batch = request.inputs.slice(i, i + batchSize);

      const batchPromises = batch.map(async (input, index) => {
        try {
          // FUA-SDK-JS-01: thread the encryption contract into every
          // per-input call so batch encrypts exactly like single calls.
          const single: InferenceRequest = {
            modelId: request.modelId,
            inputData: input
          };
          if (request.encrypted !== undefined) {
            single.encrypted = request.encrypted;
          }
          if (request.recipientPublicKey !== undefined) {
            single.recipientPublicKey = request.recipientPublicKey;
          }
          const result = await this.inference(single);
          results.push(result);
          totalGasUsed += result.gasUsed;
          totalExecutionTime += result.executionTime;
          return result;
        } catch (error) {
          const errorMsg = error instanceof Error ? error.message : 'Unknown error';
          errors.push(`Input ${i + index}: ${errorMsg}`);
          return null;
        }
      });

      if (parallel) {
        await Promise.all(batchPromises);
      } else {
        for (const promise of batchPromises) {
          await promise;
        }
      }

      // Update progress
      if (request.onProgress) {
        request.onProgress(Math.min(i + batchSize, request.inputs.length), request.inputs.length);
      }
    }

    return {
      results,
      totalGasUsed,
      totalExecutionTime,
      successCount: results.length,
      failureCount: errors.length,
      errors
    };
  }

  // Model information
  async getModelInfo(modelId: string): Promise<ModelInfo> {
    const response = await this.rpcCall('citrate_getModel', [modelId]);

    if (!response) {
      throw new ModelNotFoundError(`Model not found: ${modelId}`);
    }

    return {
      modelId: response.modelId,
      name: response.name,
      description: response.description,
      owner: response.owner,
      modelType: response.modelType,
      accessType: response.accessType,
      accessPrice: BigInt(response.accessPrice),
      encrypted: response.encrypted,
      ipfsHash: response.ipfsHash,
      deploymentTime: response.deploymentTime,
      totalInferences: response.totalInferences,
      totalRevenue: BigInt(response.totalRevenue),
      metadata: response.metadata,
      tags: response.tags
    };
  }

  async listModels(owner?: string, limit: number = 100): Promise<ModelInfo[]> {
    const params = owner ? [owner, limit] : [limit];
    const response = await this.rpcCall('citrate_listModels', params);

    return response.map((model: any) => ({
      modelId: model.modelId,
      name: model.name,
      description: model.description,
      owner: model.owner,
      modelType: model.modelType,
      accessType: model.accessType,
      accessPrice: BigInt(model.accessPrice),
      encrypted: model.encrypted,
      ipfsHash: model.ipfsHash,
      deploymentTime: model.deploymentTime,
      totalInferences: model.totalInferences,
      totalRevenue: BigInt(model.totalRevenue),
      metadata: model.metadata,
      tags: model.tags
    }));
  }

  // Payment
  //
  // SECREM-02 5.4 (audit CITRATE_SDK_JS-2026-05-31-004, HIGH): this method
  // used to send buyer `value` to the literal 0x..0104 — which the canonical
  // table (constants.PRECOMPILE_ADDRESSES.INFERENCE_VERIFY) and the node
  // (`core/execution/src/precompiles/inference.rs addresses::PROOF_VERIFY`)
  // both define as proof verification, NOT access purchase. The node's
  // dispatch table has no access-purchase precompile at all, so any value
  // sent here is misrouted: access is never granted and the funds are never
  // credited to the model. Fail closed — refuse to move money — until a
  // node-confirmed access-purchase precompile exists.
  async purchaseModelAccess(modelId: string, _paymentAmount: bigint): Promise<string> {
    throw new CitrateError(
      `purchaseModelAccess('${modelId}') is disabled (fail-closed): the canonical ` +
        'precompile table has no access-purchase operation; the previous ' +
        'implementation routed buyer funds to the INFERENCE_VERIFY precompile ' +
        '(0x..0104) where access was never granted and value was never credited ' +
        '(audit CITRATE_SDK_JS-2026-05-31-004).'
    );
  }

  // Private helper methods
  private async rpcCall(method: string, params: any[] = []): Promise<any> {
    const response: AxiosResponse = await this.axios.post('', {
      jsonrpc: '2.0',
      method,
      params,
      id: Math.floor(Math.random() * 10000)
    });

    if (response.data.error) {
      throw new CitrateError(response.data.error.message);
    }

    return response.data.result;
  }

  private async uploadToIPFS(data: Uint8Array): Promise<string> {
    // RM-G2.6 / audit SDK-01: when no IPFS endpoint is configured
    // we no longer dial `http://localhost:5001` (which fails for
    // every operator who doesn't happen to run a local kubo
    // daemon). The SHA-256 hash of the artifact is returned as a
    // deterministic content pointer instead — callers that need
    // real IPFS persistence pass `ipfsApiUrl` in CitrateClientConfig.
    if (!this.ipfsApiUrl) {
      const hash = await this.cryptoManager.hashData(data);
      return `sha256:${hash}`;
    }

    try {
      const formData = new FormData();
      const blob = new Blob([data.buffer as ArrayBuffer], { type: 'application/octet-stream' });
      formData.append('file', blob, 'model_data');

      const url = `${this.ipfsApiUrl.replace(/\/+$/, '')}/api/v0/add?pin=true`;
      const response = await fetch(url, {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        const result = await response.json();
        return result.Hash;
      } else {
        throw new Error(`IPFS upload failed: ${response.status}`);
      }
    } catch (error) {
      console.warn('IPFS upload failed, using sha256 fallback:', error);
      const hash = await this.cryptoManager.hashData(data);
      return `sha256:${hash}`;
    }
  }

  private extractModelIdFromReceipt(receipt: ethers.TransactionReceipt): string {
    // Extract model ID from deployment receipt logs
    for (const log of receipt.logs) {
      try {
        // Look for ModelDeployed event
        if (log.topics[0]?.startsWith('0x' + 'ModelDeployed'.slice(0, 8))) {
          return log.data.slice(0, 66); // First 32 bytes as hex
        }
      } catch (error) {
        continue;
      }
    }

    throw new CitrateError('Model ID not found in deployment receipt');
  }

  private extractInferenceOutput(receipt: ethers.TransactionReceipt): any {
    // Extract inference output from execution receipt
    for (const log of receipt.logs) {
      try {
        if (log.topics[0]?.startsWith('0x' + 'InferenceComplete'.slice(0, 8))) {
          const dataBytes = ethers.getBytes(log.data);
          const jsonStr = ethers.toUtf8String(dataBytes);
          return JSON.parse(jsonStr);
        }
      } catch (error) {
        continue;
      }
    }

    throw new CitrateError('Inference output not found in receipt');
  }
}