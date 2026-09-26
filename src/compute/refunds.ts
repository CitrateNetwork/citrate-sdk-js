/**
 * Compute refund claims.
 *
 * When a compute contract cannot push a refund to its requester, it credits
 * the amount and the owed account claims it (pull payment):
 *
 * | Contract              | Owed view                            | Claim                          |
 * |-----------------------|--------------------------------------|--------------------------------|
 * | InferenceRouter       | `refundOwed(address)`                | `claimRefund()`                |
 * | ComputeMarketplace    | `nativeRefundOwed(address)`          | `claimNativeRefund()`          |
 * | ComputePoolTraining   | `requesterRefundPending(uint256)`    | `claimRequesterRefund(uint256)`|
 *
 * Signatures follow citrate-chain `contracts/src` at main 0721f4b0. Each claim
 * reads the owed amount first and throws {@link NothingToClaimError} instead of
 * sending a transaction the contract would revert.
 */
import { Interface } from 'ethers';
import { CitrateError } from '../errors/CitrateError';
import { CONTRACT_ADDRESSES } from '../utils/constants';

const ABI = new Interface([
  'function claimRefund()',
  'function claimNativeRefund()',
  'function claimRequesterRefund(uint256 jobId)',
  'function refundOwed(address) view returns (uint256)',
  'function nativeRefundOwed(address) view returns (uint256)',
  'function requesterRefundPending(uint256) view returns (uint128)',
]);

function sel(name: string): string {
  const f = ABI.getFunction(name);
  if (!f) throw new Error(`missing ABI fragment ${name}`);
  return f.selector;
}

/** 4-byte selectors of the refund surface (pinned by tests). */
export const COMPUTE_REFUND_SELECTORS = Object.freeze({
  claimRefund: sel('claimRefund'),
  claimNativeRefund: sel('claimNativeRefund'),
  claimRequesterRefund: sel('claimRequesterRefund'),
  refundOwed: sel('refundOwed'),
  nativeRefundOwed: sel('nativeRefundOwed'),
  requesterRefundPending: sel('requesterRefundPending'),
});

/** Thrown by a claim when the contract owes the caller nothing. */
export class NothingToClaimError extends CitrateError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'NOTHING_TO_CLAIM', details);
    this.name = 'NothingToClaimError';
  }
}

/**
 * The subset of an ethers v6 `Signer` / `Provider` this module uses. A
 * `Provider` is enough for the views; claims need `sendTransaction` and
 * `getAddress` (a `Signer`).
 */
export interface RefundRunner {
  call(tx: { to: string; data: string }): Promise<string>;
  sendTransaction?(tx: { to: string; data: string }): Promise<unknown>;
  getAddress?(): Promise<string>;
}

export interface ComputeRefundAddresses {
  computeMarketplace: string;
  inferenceRouter: string;
  computePoolTraining: string;
}

function checkJobId(jobId: bigint | number): bigint {
  if (typeof jobId === 'number' && !Number.isSafeInteger(jobId)) {
    throw new CitrateError('jobId must be a non-negative integer', 'INVALID_ARGUMENT');
  }
  const id = BigInt(jobId);
  if (id < 0n) {
    throw new CitrateError('jobId must be a non-negative integer', 'INVALID_ARGUMENT');
  }
  return id;
}

function pick(given: string | undefined, name: string): string {
  const addr = given ?? (CONTRACT_ADDRESSES as Record<string, string | undefined>)[name];
  if (!addr) {
    throw new CitrateError(`no ${name} address configured`, 'MISSING_ADDRESS');
  }
  return addr;
}

export class ComputeRefunds {
  readonly addresses: ComputeRefundAddresses;

  constructor(
    private readonly runner: RefundRunner,
    addresses: Partial<ComputeRefundAddresses> = {},
  ) {
    this.addresses = {
      computeMarketplace: pick(addresses.computeMarketplace, 'ComputeMarketplace'),
      inferenceRouter: pick(addresses.inferenceRouter, 'InferenceRouter'),
      computePoolTraining: pick(addresses.computePoolTraining, 'ComputePoolTraining'),
    };
  }

  private async view(to: string, name: string, args: unknown[]): Promise<bigint> {
    const data = ABI.encodeFunctionData(name, args);
    const out = await this.runner.call({ to, data });
    const [v] = ABI.decodeFunctionResult(name, out);
    return BigInt(v);
  }

  /** The signer's address and send function; throws for a read-only runner. */
  private signer(name: string): {
    getAddress: () => Promise<string>;
    sendTransaction: (tx: { to: string; data: string }) => Promise<unknown>;
  } {
    const { getAddress, sendTransaction } = this.runner;
    if (!getAddress || !sendTransaction) {
      throw new CitrateError(`${name} needs a signer (getAddress + sendTransaction)`, 'NO_SIGNER');
    }
    return {
      getAddress: () => getAddress.call(this.runner),
      sendTransaction: (tx) => sendTransaction.call(this.runner, tx),
    };
  }

  private async claim(
    name: 'claimRefund' | 'claimNativeRefund' | 'claimRequesterRefund',
    to: string,
    args: unknown[],
    owed: (me: string) => Promise<bigint>,
    nothing: () => NothingToClaimError,
  ): Promise<unknown> {
    const s = this.signer(name);
    if ((await owed(await s.getAddress())) === 0n) throw nothing();
    return s.sendTransaction({ to, data: ABI.encodeFunctionData(name, args) });
  }

  /** `InferenceRouter.refundOwed(account)`. */
  refundOwed(account: string): Promise<bigint> {
    return this.view(this.addresses.inferenceRouter, 'refundOwed', [account]);
  }

  /** `ComputeMarketplace.nativeRefundOwed(account)`. */
  nativeRefundOwed(account: string): Promise<bigint> {
    return this.view(this.addresses.computeMarketplace, 'nativeRefundOwed', [account]);
  }

  /** `ComputePoolTraining.requesterRefundPending(jobId)`. */
  async requesterRefundPending(jobId: bigint | number): Promise<bigint> {
    const id = checkJobId(jobId);
    return this.view(this.addresses.computePoolTraining, 'requesterRefundPending', [id]);
  }

  /** `InferenceRouter.claimRefund()` for the signer. */
  claimRefund(): Promise<unknown> {
    return this.claim(
      'claimRefund',
      this.addresses.inferenceRouter,
      [],
      (me) => this.refundOwed(me),
      () => new NothingToClaimError('InferenceRouter owes this account nothing'),
    );
  }

  /** `ComputeMarketplace.claimNativeRefund()` for the signer. */
  claimNativeRefund(): Promise<unknown> {
    return this.claim(
      'claimNativeRefund',
      this.addresses.computeMarketplace,
      [],
      (me) => this.nativeRefundOwed(me),
      () => new NothingToClaimError('ComputeMarketplace owes this account nothing'),
    );
  }

  /**
   * `ComputePoolTraining.claimRequesterRefund(jobId)`. Only the job's
   * requester may claim; the contract enforces that.
   */
  async claimRequesterRefund(jobId: bigint | number): Promise<unknown> {
    const id = checkJobId(jobId);
    return this.claim(
      'claimRequesterRefund',
      this.addresses.computePoolTraining,
      [id],
      () => this.requesterRefundPending(id),
      () =>
        new NothingToClaimError(`no requester refund pending for training job ${id}`, {
          jobId: id.toString(),
        }),
    );
  }
}
