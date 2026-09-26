/**
 * Main Citrate client for JavaScript/TypeScript SDK
 */

import { ethers } from 'ethers';
import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { CryptoManager } from '../crypto/CryptoManager';
import { KeyManager } from '../crypto/KeyManager';
import { assertNoKeyShareMaterial, assertPayloadHasNoKeyShareMaterial } from '../crypto/shareGuard';
import {
  ModelConfig,
  ModelDeployment,
  KeyShareEnvelope,
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
import { PRECOMPILE_ADDRESSES, SDK_VERSION } from '../utils/constants';
import { enforceTransportSecurity } from '../utils/transport';

// SJS-B-003 (mirrors Python SPY-B-006): receipt log topics are keccak256 of the
// event signature, NOT the ASCII hex of the event name. The pre-fix matcher
// compared topics[0] against `'0x' + 'ModelDeployed'.slice(0,8)` === `'0xModelDep'`,
// which contains characters ('M','o','d','l','P') that cannot appear in a hex
// topic, so it NEVER matched and both flagship methods always threw AFTER
// broadcasting (and paying gas). Match the real keccak topic via `ethers.id`.
// If the node's ABI differs, change the signature here — one place, and the
// fixture derives its topic from the same constant so the two cannot drift.
export const MODEL_DEPLOYED_EVENT_SIGNATURE = 'ModelDeployed(bytes32,address)';
export const INFERENCE_COMPLETE_EVENT_SIGNATURE = 'InferenceComplete(bytes32,bytes)';

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
  /**
   * Opt in to remote plaintext transport (SJS-B / SPY-B-009). By default the
   * client FAILS CLOSED on a remote `http://`/`ws://` RPC or IPFS endpoint —
   * signed transactions, private inputs and any credentials would otherwise go
   * out in cleartext. Loopback/localhost is always allowed. Set true only for a
   * trusted internal network without TLS.
   */
  allowInsecureHttp?: boolean;
}

export class CitrateClient {
  private provider: ethers.JsonRpcProvider | ethers.FallbackProvider;
  private wallet?: ethers.Wallet;
  private axios: AxiosInstance;
  /**
   * SJS-B-008 — one axios instance per RPC URL, primary first. `rpcCall`
   * iterates this list on transport errors so a single broken endpoint does not
   * take the integration down. Before this fix the advertised multi-RPC
   * failover did not exist: `selectRpc` was named in a comment but never
   * implemented, and every request went to `rpcUrls[0]` only.
   */
  private readonly axiosPool: AxiosInstance[];
  private keyManager?: KeyManager;
  private cryptoManager: CryptoManager;
  /** RM-G2.6 / SDK-02 — full fallback list, primary first. */
  private readonly rpcUrls: readonly string[];
  /** RM-G2.6 / SDK-01 — undefined means "no IPFS configured". */
  private readonly ipfsApiUrl: string | undefined;
  /** SJS-B / SPY-B-009 — opt-in to remote plaintext endpoints. */
  private readonly allowInsecureHttp: boolean;

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
    this.allowInsecureHttp = config.allowInsecureHttp ?? false;
    // SJS-B / SPY-B-009: fail closed on a remote plaintext RPC endpoint before
    // any provider is built. Loopback passes; the caller opts in for internal
    // TLS-less networks via allowInsecureHttp.
    for (const url of this.rpcUrls) {
      enforceTransportSecurity(url, { allowInsecureHttp: this.allowInsecureHttp });
    }
    const primaryRpc = this.rpcUrls[0] as string;

    // Initialize provider. With a single URL this is a plain JsonRpcProvider;
    // with several, ethers.FallbackProvider gives genuine automatic failover so
    // the multi-RPC claim in CitrateClientConfig is actually true (SJS-B-008).
    this.provider = this.rpcUrls.length > 1
      ? new ethers.FallbackProvider(
          this.rpcUrls.map((u, i) => ({
            provider: new ethers.JsonRpcProvider(u),
            priority: i + 1,
            weight: 1,
          })),
        )
      : new ethers.JsonRpcProvider(primaryRpc);

    // Initialize wallet if private key provided
    if (config.privateKey) {
      this.wallet = new ethers.Wallet(config.privateKey, this.provider);
      this.keyManager = new KeyManager(config.privateKey);
    }

    // Initialize one HTTP client per RPC URL so rpcCall can fail over. The UA is
    // derived from SDK_VERSION (SJS-B-H03) rather than a hardcoded stale string.
    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': `citrate-js-sdk/${SDK_VERSION}`,
      ...config.headers,
    };
    this.axiosPool = this.rpcUrls.map((url) =>
      axios.create({ baseURL: url, timeout: config.timeout || 30000, headers }),
    );
    this.axios = this.axiosPool[0] as AxiosInstance;

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
    for (const instance of this.axiosPool) {
      // Request interceptor for logging
      instance.interceptors.request.use(
        (config) => {
          console.debug('Citrate API Request:', config.method?.toUpperCase(), config.url);
          return config;
        },
        (error) => Promise.reject(error)
      );

      // Response interceptor for error handling
      instance.interceptors.response.use(
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
    let keyShareEnvelopes: KeyShareEnvelope[] | undefined;

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
      keyShareEnvelopes = result.keyShareEnvelopes;
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

    // PBA-L4-001: this calldata is public. Guard the transaction data, then
    // serialise once, guard those exact bytes (duplicate keys refused), and
    // send the same bytes. The first check is defence in depth: the payload
    // guard also recognises the JSON renderings of byte values.
    assertNoKeyShareMaterial(txData);
    const wire = JSON.stringify(txData);
    assertPayloadHasNoKeyShareMaterial(wire);

    // Deploy to blockchain — canonical INFERENCE_DEPLOY precompile from
    // constants (audit -004: no hardcoded address literals in the client).
    const tx = await this.wallet.sendTransaction({
      to: PRECOMPILE_ADDRESSES.INFERENCE_DEPLOY,
      data: ethers.hexlify(ethers.toUtf8Bytes(wire)),
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
      gasUsed: receipt.gasUsed,
      ...(keyShareEnvelopes ? { keyShareEnvelopes } : {})
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
  //
  // SJS-B-008: iterate the axios pool (one instance per RPC URL) so a single
  // broken endpoint does not take the call down. A *transport* error (no
  // response — DNS, connection refused, timeout) rotates to the next endpoint;
  // a JSON-RPC error carried in a 2xx body is a real protocol answer and is NOT
  // retried (retrying it would just duplicate the request against every node).
  private async rpcCall(method: string, params: any[] = []): Promise<any> {
    const payload = {
      jsonrpc: '2.0',
      method,
      params,
      id: Math.floor(Math.random() * 10000),
    };

    let lastError: unknown;
    for (let i = 0; i < this.axiosPool.length; i++) {
      const instance = this.axiosPool[i] as AxiosInstance;
      try {
        const response: AxiosResponse = await instance.post('', payload);
        if (response.data.error) {
          throw new CitrateError(response.data.error.message);
        }
        return response.data.result;
      } catch (error) {
        // A CitrateError raised from a JSON-RPC error body is an authoritative
        // answer from a reachable node — surface it, do not fail over.
        if (error instanceof CitrateError && !/^Network error:/.test(error.message)) {
          throw error;
        }
        lastError = error;
        // otherwise: transport failure — try the next endpoint.
      }
    }
    throw lastError instanceof Error
      ? lastError
      : new CitrateError('rpcCall: all RPC endpoints failed');
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

    // SJS-B / SPY-B-009: refuse to POST the (possibly private) artifact to a
    // remote plaintext IPFS endpoint unless the caller opted in.
    const base = enforceTransportSecurity(this.ipfsApiUrl.replace(/\/+$/, ''), {
      allowInsecureHttp: this.allowInsecureHttp,
    });

    // SJS-B-005 (mirrors Python CIT-SDKPY-03): FAIL CLOSED. This previously
    // swallowed any upload error, logged a console.warn, and returned a
    // `sha256:<hash>` pseudo-pointer — so `deployModel` recorded a permanent
    // on-chain artifact pointer to bytes that exist nowhere, while the caller
    // (who routinely does not read console.warn) believed it succeeded. A
    // hostile or misconfigured endpoint could force every deployment to be a
    // silent dud. Surface the failure instead: the caller decides whether to
    // retry or fall back to a content hash, rather than the SDK deciding
    // silently. When no IPFS endpoint is configured the hash-only pointer above
    // is the explicit, documented opt-out.
    const formData = new FormData();
    const blob = new Blob([data.buffer as ArrayBuffer], { type: 'application/octet-stream' });
    formData.append('file', blob, 'model_data');

    const url = `${base}/api/v0/add?pin=true`;
    let response: Response;
    try {
      response = await fetch(url, {
        method: 'POST',
        body: formData,
        // Bound the request so a hanging endpoint cannot wedge a deployment.
        signal: AbortSignal.timeout(60_000),
      });
    } catch (error) {
      throw new CitrateError(
        `IPFS upload to ${base} failed at the transport layer: ` +
          `${error instanceof Error ? error.message : String(error)}. ` +
          'Refusing to record a non-retrievable artifact pointer on-chain ' +
          '(SJS-B-005). Fix the endpoint or omit ipfsApiUrl to use a content hash.',
      );
    }

    if (!response.ok) {
      throw new CitrateError(
        `IPFS upload to ${base} failed: HTTP ${response.status}. ` +
          'Refusing to record a non-retrievable artifact pointer on-chain ' +
          '(SJS-B-005).',
      );
    }
    const result = await response.json();
    if (!result || typeof result.Hash !== 'string' || result.Hash.length === 0) {
      throw new CitrateError(
        `IPFS upload to ${base} returned no CID (malformed add response). ` +
          'Refusing to record a non-retrievable artifact pointer on-chain (SJS-B-005).',
      );
    }
    return result.Hash;
  }

  private extractModelIdFromReceipt(receipt: ethers.TransactionReceipt): string {
    // SJS-B-003: match the real keccak topic, not the impossible ASCII literal.
    const wantTopic = ethers.id(MODEL_DEPLOYED_EVENT_SIGNATURE);
    for (const log of receipt.logs) {
      try {
        if (log.topics[0]?.toLowerCase() === wantTopic) {
          // Prefer the indexed modelId in topics[1]; fall back to the first
          // 32 bytes of data for a non-indexed emitter.
          const indexed = log.topics[1];
          if (typeof indexed === 'string' && indexed.length === 66) return indexed;
          return log.data.slice(0, 66);
        }
      } catch (error) {
        continue;
      }
    }

    // Include the tx hash so a caller can recover (look the tx up, decode it
    // themselves) instead of blindly retrying and paying gas again — the money
    // cost this defect used to impose.
    throw new CitrateError(
      `Model ID not found in deployment receipt (tx ${receipt.hash}). ` +
        'The transaction was broadcast and confirmed; do not retry blindly.',
    );
  }

  private extractInferenceOutput(receipt: ethers.TransactionReceipt): any {
    // SJS-B-003: match the real keccak topic, not the impossible ASCII literal.
    const wantTopic = ethers.id(INFERENCE_COMPLETE_EVENT_SIGNATURE);
    for (const log of receipt.logs) {
      try {
        if (log.topics[0]?.toLowerCase() === wantTopic) {
          const dataBytes = ethers.getBytes(log.data);
          const jsonStr = ethers.toUtf8String(dataBytes);
          return JSON.parse(jsonStr);
        }
      } catch (error) {
        continue;
      }
    }

    throw new CitrateError(
      `Inference output not found in receipt (tx ${receipt.hash}). ` +
        'The transaction was broadcast and confirmed; do not retry blindly.',
    );
  }
}