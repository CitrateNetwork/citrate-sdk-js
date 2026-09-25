/**
 * Variant of PBA-L6b-027 (Python) in the JS SDK: verifyWalletAddressOnChain
 * trusted any provider — no chain-id assertion and no check that the factory has
 * code there — so a wrong-chain or hostile RPC could echo the (publicly
 * computable) predicted address and "verified" passed.
 */
import { AbiCoder, getAddress, type Provider } from 'ethers';
import { predictWalletAddress, verifyWalletAddressOnChain } from '../../src/identity/wallet';
import { FEDERATION_CONTRACT } from '../../src/generated/contract';

const UID = '0x' + '42'.repeat(32);

function fakeProvider(o: { chainId?: bigint; code?: string; echo?: boolean } = {}): { p: Provider; calls: string[] } {
  const calls: string[] = [];
  const local = predictWalletAddress(UID);
  const p = {
    getNetwork: async () => { calls.push('chainId'); return { chainId: o.chainId ?? 40204n }; },
    getCode: async () => { calls.push('getCode'); return o.code ?? '0x6080'; },
    call: async () => {
      calls.push('call');
      return AbiCoder.defaultAbiCoder().encode(['address'], [o.echo === false ? getAddress('0x' + '11'.repeat(20)) : local]);
    },
  } as unknown as Provider;
  return { p, calls };
}

describe('PBA-L6b-027 variant: verifyWalletAddressOnChain checks chain and factory code', () => {
  it('refuses a provider on the wrong chain even when it echoes the prediction', async () => {
    const { p, calls } = fakeProvider({ chainId: 1n });
    await expect(verifyWalletAddressOnChain(UID, p)).rejects.toThrow(/chain 1, expected chain 40204/);
    expect(calls).not.toContain('call');
  });
  it.each(['0x', '0x0', ''])('refuses a codeless factory (%p)', async (code) => {
    const { p } = fakeProvider({ code });
    await expect(verifyWalletAddressOnChain(UID, p)).rejects.toThrow(/has no code/);
  });
  it('still refuses a mismatch', async () => {
    const { p } = fakeProvider({ echo: false });
    await expect(verifyWalletAddressOnChain(UID, p)).rejects.toThrow(/do not fund/);
  });
  it('happy path checks chain, then code, then the prediction; chain id overridable', async () => {
    const { p, calls } = fakeProvider();
    await expect(verifyWalletAddressOnChain(UID, p)).resolves.toBe(predictWalletAddress(UID));
    expect(calls).toEqual(['chainId', 'getCode', 'call']);
    const dev = fakeProvider({ chainId: 31337n });
    await expect(verifyWalletAddressOnChain(UID, dev.p, { chainId: 31337 })).resolves.toBe(predictWalletAddress(UID));
    expect(FEDERATION_CONTRACT.chain.chainId).toBe(40204);
  });
});
