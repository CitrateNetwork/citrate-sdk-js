/**
 * JSON-RPC client for the Citrate ERC-4337 bundler (EW-S1 WP-7).
 *
 * Talks to `https://bundler.citrate.ai/rpc` (eth-infinitism bundler
 * v0.7 behind Caddy — see the `citrate-bundler` repo). Errors carry
 * the bundler's JSON-RPC error payload verbatim so callers can show
 * AAxx revert codes (e.g. AA21 didn't pay prefund, AA31 paymaster
 * deposit too low) instead of a generic failure.
 */

import axios, { type AxiosInstance } from 'axios';

import type {
  Address,
  Hex,
  PackedUserOperation,
  RpcUserOperation,
  UserOperationReceipt,
} from './types';
import { toRpcUserOperation } from './userop';

/** Default production endpoint. */
export const CITRATE_BUNDLER_URL = 'https://bundler.citrate.ai/rpc';

export class BundlerRpcError extends Error {
  readonly code: number;
  readonly data: unknown;

  constructor(message: string, code: number, data: unknown) {
    super(message);
    this.name = 'BundlerRpcError';
    this.code = code;
    this.data = data;
  }
}

interface JsonRpcResponse<T> {
  jsonrpc: '2.0';
  id: number;
  result?: T;
  error?: { code: number; message: string; data?: unknown };
}

export interface BundlerClientOptions {
  url?: string;
  /** `bk_`-prefixed Citrate bundler API key (WP-4 slice B), if issued. */
  apiKey?: string;
  timeoutMs?: number;
  /** Injectable for tests; defaults to a fresh axios instance. */
  http?: AxiosInstance;
}

export class BundlerClient {
  private readonly url: string;
  private readonly http: AxiosInstance;
  private nextId = 1;

  constructor(options: BundlerClientOptions = {}) {
    this.url = options.url ?? CITRATE_BUNDLER_URL;
    this.http =
      options.http ??
      axios.create({
        timeout: options.timeoutMs ?? 30_000,
        headers: {
          'content-type': 'application/json',
          ...(options.apiKey ? { authorization: `Bearer ${options.apiKey}` } : {}),
        },
      });
  }

  private async rpc<T>(method: string, params: unknown[]): Promise<T> {
    const res = await this.http.post<JsonRpcResponse<T>>(this.url, {
      jsonrpc: '2.0',
      id: this.nextId++,
      method,
      params,
    });
    const body = res.data;
    if (body.error) {
      throw new BundlerRpcError(
        `${method} failed: ${body.error.message}`,
        body.error.code,
        body.error.data,
      );
    }
    if (body.result === undefined) {
      throw new BundlerRpcError(`${method} returned no result`, -32603, body);
    }
    return body.result;
  }

  /** The chain the bundler submits to — sanity-check it equals 40204 (0x9d0c). */
  async chainId(): Promise<bigint> {
    return BigInt(await this.rpc<Hex>('eth_chainId', []));
  }

  /** EntryPoints the bundler accepts ops for. */
  async supportedEntryPoints(): Promise<Address[]> {
    return this.rpc<Address[]>('eth_supportedEntryPoints', []);
  }

  /**
   * Submit a UserOperation. Accepts the packed struct and converts to
   * the unpacked v0.7 wire shape. Returns the userOpHash.
   */
  async sendUserOperation(
    op: PackedUserOperation | RpcUserOperation,
    entryPoint: Address,
  ): Promise<Hex> {
    const wire = isPacked(op) ? toRpcUserOperation(op) : op;
    return this.rpc<Hex>('eth_sendUserOperation', [wire, entryPoint]);
  }

  /** Gas estimation for an unsigned (or dummy-signed) op. */
  async estimateUserOperationGas(
    op: PackedUserOperation | RpcUserOperation,
    entryPoint: Address,
  ): Promise<{
    preVerificationGas: Hex;
    verificationGasLimit: Hex;
    callGasLimit: Hex;
    paymasterVerificationGasLimit?: Hex;
  }> {
    const wire = isPacked(op) ? toRpcUserOperation(op) : op;
    return this.rpc('eth_estimateUserOperationGas', [wire, entryPoint]);
  }

  /** Null until the op is mined. */
  async getUserOperationReceipt(
    userOpHash: Hex,
  ): Promise<UserOperationReceipt | null> {
    return this.rpc<UserOperationReceipt | null>('eth_getUserOperationReceipt', [
      userOpHash,
    ]);
  }

  /**
   * Poll for the receipt. Citrate blocks land ~every 1.4s, so the
   * defaults (2s interval, 60s budget) cover normal inclusion plus a
   * bundle interval.
   */
  async waitForUserOperationReceipt(
    userOpHash: Hex,
    opts: { pollIntervalMs?: number; timeoutMs?: number } = {},
  ): Promise<UserOperationReceipt> {
    const interval = opts.pollIntervalMs ?? 2_000;
    const deadline = Date.now() + (opts.timeoutMs ?? 60_000);
    for (;;) {
      const receipt = await this.getUserOperationReceipt(userOpHash);
      if (receipt) return receipt;
      if (Date.now() + interval > deadline) {
        throw new BundlerRpcError(
          `timed out waiting for UserOperation receipt ${userOpHash}`,
          -32_000,
          { userOpHash },
        );
      }
      await new Promise((r) => setTimeout(r, interval));
    }
  }
}

function isPacked(
  op: PackedUserOperation | RpcUserOperation,
): op is PackedUserOperation {
  return typeof (op as PackedUserOperation).nonce === 'bigint';
}
