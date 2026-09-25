/**
 * Compute refund claims (chain main 0721f4b0).
 *
 * Refunds that the compute contracts cannot push are credited and claimed by
 * the owed account:
 *   - InferenceRouter.claimRefund()                  / refundOwed(address)
 *   - ComputeMarketplace.claimNativeRefund()         / nativeRefundOwed(address)
 *   - ComputePoolTraining.claimRequesterRefund(uint) / requesterRefundPending(uint)
 *
 * Selectors are pinned (from `cast sig`) so an ABI typo cannot drift silently.
 * The namespace is read dynamically so a missing export fails at runtime.
 */
import * as sdk from '../../src';
import { CONTRACT_ADDRESSES } from '../../src/utils/constants';

type Tx = { to: string; data: string };

const MARKET = '0x' + '11'.repeat(20);
const ROUTER = '0x' + '22'.repeat(20);
const TRAINING = '0x' + '33'.repeat(20);
const ME = '0x' + 'ab'.repeat(20);

function word(v: bigint): string {
  return '0x' + v.toString(16).padStart(64, '0');
}

/** A runner whose eth_call returns `owed` for every view; records sends. */
function runner(owed: bigint) {
  const calls: Tx[] = [];
  const sent: Tx[] = [];
  return {
    calls,
    sent,
    async call(tx: Tx) {
      calls.push(tx);
      return word(owed);
    },
    async sendTransaction(tx: Tx) {
      sent.push(tx);
      return { hash: '0x' + 'ee'.repeat(32) };
    },
    async getAddress() {
      return ME;
    },
  };
}

function compute(): any {
  const ns = (sdk as unknown as Record<string, any>).compute;
  expect(ns).toBeDefined();
  return ns;
}

function refunds(r: ReturnType<typeof runner>) {
  const { ComputeRefunds } = compute();
  return new ComputeRefunds(r, {
    computeMarketplace: MARKET,
    inferenceRouter: ROUTER,
    computePoolTraining: TRAINING,
  });
}

describe('compute refund claims', () => {
  it('pins the refund selectors', () => {
    const { COMPUTE_REFUND_SELECTORS } = compute();
    expect(COMPUTE_REFUND_SELECTORS).toEqual({
      claimRefund: '0xb5545a3c',
      claimNativeRefund: '0x3998010c',
      claimRequesterRefund: '0xec3c3fa8',
      refundOwed: '0x9abc825f',
      nativeRefundOwed: '0xf0dbade2',
      requesterRefundPending: '0x0a54e905',
    });
  });

  it('reads each owed amount from the right contract', async () => {
    const r = runner(7n);
    const c = refunds(r);
    expect(await c.nativeRefundOwed(ME)).toBe(7n);
    expect(await c.refundOwed(ME)).toBe(7n);
    expect(await c.requesterRefundPending(42n)).toBe(7n);
    expect(r.calls.map((t) => [t.to, t.data.slice(0, 10)])).toEqual([
      [MARKET, '0xf0dbade2'],
      [ROUTER, '0x9abc825f'],
      [TRAINING, '0x0a54e905'],
    ]);
    expect(r.calls[2]!.data.slice(10)).toBe(word(42n).slice(2));
    expect(r.calls[0]!.data.slice(10).toLowerCase()).toBe(ME.slice(2).padStart(64, '0'));
  });

  it('claims send the exact calldata to the right contract when something is owed', async () => {
    const r = runner(1n);
    const c = refunds(r);
    await c.claimNativeRefund();
    await c.claimRefund();
    await c.claimRequesterRefund(42n);
    expect(r.sent).toEqual([
      { to: MARKET, data: '0x3998010c' },
      { to: ROUTER, data: '0xb5545a3c' },
      { to: TRAINING, data: '0xec3c3fa8' + word(42n).slice(2) },
    ]);
  });

  it('claims fail closed without sending when nothing is owed', async () => {
    const { NothingToClaimError } = compute();
    for (const [claim, msg] of [
      ['claimNativeRefund', /^ComputeMarketplace owes this account nothing$/],
      ['claimRefund', /^InferenceRouter owes this account nothing$/],
      ['claimRequesterRefund', /^no requester refund pending for training job 1$/],
    ] as const) {
      const r = runner(0n);
      const c = refunds(r);
      const err = await c[claim](1n).then(
        () => null,
        (e: unknown) => e as { code: string; name: string; message: string; details?: unknown },
      );
      expect(err).toBeInstanceOf(NothingToClaimError);
      expect(err!.code).toBe('NOTHING_TO_CLAIM');
      expect(err!.name).toBe('NothingToClaimError');
      expect(err!.message).toMatch(msg);
      expect(err!.details).toEqual(claim === 'claimRequesterRefund' ? { jobId: '1' } : undefined);
      expect(r.sent).toHaveLength(0);
    }
  });

  it('accepts job id 0', async () => {
    const r = runner(1n);
    await refunds(r).claimRequesterRefund(0n);
    expect(r.sent[0]!.data).toBe('0xec3c3fa8' + word(0n).slice(2));
  });

  it('needs both getAddress and sendTransaction to claim', async () => {
    const base = runner(1n);
    for (const partial of [
      { call: base.call },
      { call: base.call, getAddress: base.getAddress },
      { call: base.call, sendTransaction: base.sendTransaction },
    ]) {
      const c = refunds(partial as any);
      for (const claim of ['claimNativeRefund', 'claimRefund', 'claimRequesterRefund'] as const) {
        await expect(c[claim](1n)).rejects.toMatchObject({
          code: 'NO_SIGNER',
          message: `${claim} needs a signer (getAddress + sendTransaction)`,
        });
      }
    }
    expect(base.sent).toHaveLength(0);
  });

  it('refuses an empty contract address', () => {
    const { ComputeRefunds } = compute();
    for (const [key, name] of [
      ['computeMarketplace', 'ComputeMarketplace'],
      ['inferenceRouter', 'InferenceRouter'],
      ['computePoolTraining', 'ComputePoolTraining'],
    ] as const) {
      expect(() => new ComputeRefunds(runner(0n), { [key]: '' })).toThrow(
        expect.objectContaining({ code: 'MISSING_ADDRESS', message: `no ${name} address configured` }),
      );
    }
  });

  it('checks the signer own balance, not an arbitrary account', async () => {
    const r = runner(5n);
    const c = refunds(r);
    await c.claimNativeRefund();
    await c.claimRefund();
    // The pre-check views were keyed by the signer address.
    for (const t of r.calls.slice(0, 2)) {
      expect(t.data.slice(10).toLowerCase()).toBe(ME.slice(2).padStart(64, '0'));
    }
  });


  it('rejects a negative or non-integer job id', async () => {
    const c = refunds(runner(1n));
    for (const bad of [-1n, 1.5, Number.MAX_SAFE_INTEGER + 2]) {
      await expect(c.requesterRefundPending(bad as any)).rejects.toMatchObject({
        code: 'INVALID_ARGUMENT',
        message: 'jobId must be a non-negative integer',
      });
      await expect(c.claimRequesterRefund(bad as any)).rejects.toMatchObject({
        code: 'INVALID_ARGUMENT',
      });
    }
  });

  it('defaults to the federation contract addresses', () => {
    const { ComputeRefunds } = compute();
    const c = new ComputeRefunds(runner(0n));
    expect(c.addresses).toEqual({
      computeMarketplace: CONTRACT_ADDRESSES.ComputeMarketplace,
      inferenceRouter: CONTRACT_ADDRESSES.InferenceRouter,
      computePoolTraining: CONTRACT_ADDRESSES.ComputePoolTraining,
    });
  });
});
