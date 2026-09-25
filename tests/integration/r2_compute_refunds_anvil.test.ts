/**
 * Compute refund claims against a local anvil running the chain-main compute
 * contracts. Skipped unless CITRATE_R2_ANVIL_ADDRS points at a JSON file of
 * deployed addresses ({ InferenceRouter, ComputeMarketplace,
 * ComputePoolTraining }); CITRATE_R2_ANVIL_RPC defaults to 127.0.0.1:8599.
 *
 * Uses anvil default accounts 5 (provider) and 6 (requester) only.
 */
import { readFileSync } from 'node:fs';
import { JsonRpcProvider, Wallet, Contract, NonceManager, parseEther, keccak256, toUtf8Bytes } from 'ethers';
import * as sdk from '../../src';

const ADDRS = process.env.CITRATE_R2_ANVIL_ADDRS;
const RPC = process.env.CITRATE_R2_ANVIL_RPC ?? 'http://127.0.0.1:8599';
const KEY5 = '0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba';
const KEY6 = '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e';

const maybe = ADDRS ? describe : describe.skip;

maybe('compute refund claims on anvil (chain main)', () => {
  const addrs = ADDRS ? JSON.parse(readFileSync(ADDRS, 'utf8')) : {};
  const provider = new JsonRpcProvider(RPC);
  const providerKey = new NonceManager(new Wallet(KEY5, provider));
  const requester = new NonceManager(new Wallet(KEY6, provider));
  const model = keccak256(toUtf8Bytes('r2-sdk-js-refund-model'));
  const refunds = () =>
    new sdk.compute.ComputeRefunds(requester, {
      computeMarketplace: addrs.ComputeMarketplace,
      inferenceRouter: addrs.InferenceRouter,
      computePoolTraining: addrs.ComputePoolTraining,
    });

  afterAll(() => provider.destroy());

  it('InferenceRouter: an over-payment is credited and claimRefund pays it out', async () => {
    const router = new Contract(
      addrs.InferenceRouter,
      [
        'function registerProvider(string,uint256,bytes32[]) payable',
        'function requestInference(bytes32,bytes,uint256) payable returns (uint256)',
        'function providers(address) view returns (address,string,uint256,uint256,uint256,uint256,uint256,uint256,uint256,bool)',
      ],
      providerKey,
    );
    try {
      await (await router.getFunction('registerProvider')('https://p.example', 1n, [model], { value: parseEther('100') })).wait();
    } catch (e) {
      if (!String(e).includes('Provider already registered')) throw e;
    }

    const me = await requester.getAddress();
    const c = refunds();
    const before = await c.refundOwed(me);
    const input = toUtf8Bytes(`r2-${Date.now()}-${Math.random()}`);
    await (
      await (router.connect(requester) as Contract).getFunction('requestInference')(model, input, parseEther('1'), {
        value: parseEther('2'),
      })
    ).wait();
    expect(await c.refundOwed(me)).toBe(before + parseEther('1'));

    const tx = (await c.claimRefund()) as {
      wait(): Promise<{ gasUsed: bigint; gasPrice: bigint; blockNumber: number }>;
    };
    const rc = await tx.wait();
    const bal0 = await provider.getBalance(me, rc.blockNumber - 1);
    const bal1 = await provider.getBalance(me, rc.blockNumber);
    expect(bal1 - bal0 + rc.gasUsed * rc.gasPrice).toBe(before + parseEther('1'));
    expect(await c.refundOwed(me)).toBe(0n);
    await expect(c.claimRefund()).rejects.toBeInstanceOf(sdk.compute.NothingToClaimError);
  });

  it('ComputeMarketplace / ComputePoolTraining: the claim entry points exist on the deployed bytecode', async () => {
    const me = await requester.getAddress();
    const c = refunds();
    expect(await c.nativeRefundOwed(me)).toBe(0n);
    expect(await c.requesterRefundPending(999_999n)).toBe(0n);
    await expect(c.claimNativeRefund()).rejects.toBeInstanceOf(sdk.compute.NothingToClaimError);
    await expect(c.claimRequesterRefund(999_999n)).rejects.toBeInstanceOf(sdk.compute.NothingToClaimError);

    // The raw calls reach the real functions (their own revert reasons, not a
    // missing-selector fallback revert).
    const { COMPUTE_REFUND_SELECTORS: S } = sdk.compute;
    await expect(provider.call({ from: me, to: addrs.ComputeMarketplace, data: S.claimNativeRefund })).rejects.toThrow(
      /nothing owed/,
    );
    await expect(
      provider.call({
        from: me,
        to: addrs.ComputePoolTraining,
        data: S.claimRequesterRefund + (999_999).toString(16).padStart(64, '0'),
      }),
    ).rejects.toThrow(/not requester/);
  });
});
