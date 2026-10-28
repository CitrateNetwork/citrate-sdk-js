/**
 * r1006 address book + genesis guard.
 *
 * r1005 and r1006 share chain id 40204, so a chain-id check cannot tell them apart. The
 * address book vendored here is the r1006 book (citrate-chain
 * `contracts/addresses/r1006/40204.json`, via citrate-federation gen-contract), and the
 * federation artifact carries the r1006 block-0 hash (`R1006_GENESIS` in citrate-chain
 * core/consensus/src/hardening.rs). Every path that pairs a book address with an RPC
 * reads block 0 first and refuses another network.
 */
import { AbiCoder, getAddress, type Provider } from 'ethers';
import { CitrateClient } from '../../src/client/CitrateClient';
import { ComputeRefunds } from '../../src/compute/refunds';
import { FEDERATION_CONTRACT } from '../../src/generated/contract';
import { predictWalletAddress, verifyWalletAddressOnChain } from '../../src/identity/wallet';
import {
  AA_ADDRESSES,
  CONTRACT_ADDRESSES,
  MEMBERSHIP_ADDRESSES,
} from '../../src/utils/constants';
import { EXPECTED_GENESIS_HASH, WrongNetworkError, assertGenesis } from '../../src/utils/network';
import * as sdk from '../../src';

const R1006_GENESIS = '0xa3651a272fe411948cbb4cf7cca4cee44be4248d32ab4376cea7636821c6cdd4';
const R1005_GENESIS = '0x1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1';
const OWNER = '0x' + '11'.repeat(32);

describe('vendored address book is the r1006 book', () => {
  it('carries the r1006 genesis hash and exports it', () => {
    expect(FEDERATION_CONTRACT.chain.genesisHash).toBe(R1006_GENESIS);
    expect(EXPECTED_GENESIS_HASH).toBe(R1006_GENESIS);
    expect((sdk as Record<string, unknown>).EXPECTED_GENESIS_HASH).toBe(R1006_GENESIS);
  });

  it('points the AA stack and membership at the r1006 contracts', () => {
    expect(AA_ADDRESSES.CitrateWalletFactory.toLowerCase()).toBe('0x6ee3b59099c9c812cdf1c9e7e6ff166b2558434c');
    expect(AA_ADDRESSES.CitratePaymaster.toLowerCase()).toBe('0x5a1e2d73f8154a01a78b56e551c977cb8327ff56');
    expect(MEMBERSHIP_ADDRESSES.CitrateMemberSBT?.toLowerCase()).toBe('0x883165132776171fbcfde2d3c789ef5bdb0d060d');
    expect(CONTRACT_ADDRESSES.ComputeMarketplace?.toLowerCase()).toBe('0x2fec2ac1dde3a1a749c84d487738904cd2ed50c2');
  });

  it('drops contracts that are not in r1006 block 0', () => {
    for (const gone of ['LiquidStakingPool', 'CitAgentTimelock', 'DefensePrimeComplianceRegistry', 'TenantHierarchy']) {
      expect(Object.keys(CONTRACT_ADDRESSES)).not.toContain(gone);
    }
  });

  it('leaks no r1005 address that moved at r1006', () => {
    const blob = JSON.stringify(FEDERATION_CONTRACT).toLowerCase();
    for (const dead of ['0x9ac05ad6', '0x804a8021', '0xf8ad11f6', '0xa93f7f68', '0x73270e98', '0xa96a891b']) {
      expect(blob).not.toContain(dead);
    }
  });
});

/** A provider double that answers block 0 with `genesis` and records what it was asked. */
function chainDouble(genesis: string | null, extra: Record<string, unknown> = {}) {
  const calls: string[] = [];
  const p = {
    getBlock: async (tag: number) => {
      calls.push(`getBlock:${tag}`);
      return genesis === null ? null : { hash: genesis, number: 0 };
    },
    ...extra,
  };
  return { p, calls };
}

/** A provider double whose block 0 is answered from `answers` in turn ('throw' = an RPC error). */
function switchingDouble(answers: Array<string | 'throw'>) {
  let n = 0;
  const p = {
    getBlock: async (tag: number) => {
      expect(tag).toBe(0);
      const a = answers[Math.min(n, answers.length - 1)] as string;
      n += 1;
      if (a === 'throw') throw new Error('connection reset');
      return { hash: a, number: 0 };
    },
  };
  return { p, reads: () => n };
}

describe('assertGenesis', () => {
  it('fails closed when getBlock throws, and names the cause', async () => {
    const err = await assertGenesis(switchingDouble(['throw']).p, R1006_GENESIS).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WrongNetworkError);
    expect((err as Error).message).toContain('connection reset');
  });

  it('fails closed on a block without a hash', async () => {
    await expect(assertGenesis({ getBlock: async () => ({ hash: null }) }, R1006_GENESIS)).rejects.toThrow(
      WrongNetworkError,
    );
  });

  it('passes on the expected hash', async () => {
    await expect(assertGenesis(switchingDouble([R1006_GENESIS]).p, R1006_GENESIS)).resolves.toBeUndefined();
  });
});

describe('CitrateClient refuses an RPC on another genesis', () => {
  function client(genesis: string | null, cfg: Record<string, unknown> = {}) {
    const c = new CitrateClient({ rpcUrl: 'http://127.0.0.1:8545', privateKey: OWNER, ...cfg });
    const { p, calls } = chainDouble(genesis);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any).provider = p;
    const sent: unknown[] = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any).wallet.sendTransaction = async (tx: unknown) => {
      sent.push(tx);
      throw new Error('sent');
    };
    return { c, calls, sent };
  }

  it('verifyNetwork rejects an r1005 node with WrongNetworkError naming both hashes', async () => {
    const { c } = client(R1005_GENESIS);
    const err = await c.verifyNetwork().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WrongNetworkError);
    expect((err as WrongNetworkError).code).toBe('WRONG_NETWORK');
    expect((err as Error).message).toContain(R1005_GENESIS);
    expect((err as Error).message).toContain(R1006_GENESIS);
  });

  it('verifyNetwork accepts the r1006 genesis (any case) and reads block 0 once', async () => {
    const { c, calls } = client(R1006_GENESIS.toUpperCase().replace('0X', '0x'));
    await expect(c.verifyNetwork()).resolves.toBeUndefined();
    await expect(c.verifyNetwork()).resolves.toBeUndefined();
    expect(calls).toEqual(['getBlock:0']);
  });

  it('fails closed when the RPC has no block 0', async () => {
    const { c } = client(null);
    await expect(c.verifyNetwork()).rejects.toThrow(WrongNetworkError);
  });

  it('a failed check is not cached as success', async () => {
    const { c } = client(R1005_GENESIS);
    await expect(c.verifyNetwork()).rejects.toThrow(WrongNetworkError);
    await expect(c.verifyNetwork()).rejects.toThrow(WrongNetworkError);
  });

  it('fails closed when block 0 cannot be read (the RPC errors)', async () => {
    const { c, sent } = client(R1006_GENESIS);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any).provider = {
      getBlock: async () => {
        throw new Error('connection reset');
      },
    };
    const err = await c.verifyNetwork().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WrongNetworkError);
    expect((err as Error).message).toMatch(/cannot read block 0/);
    await expect(
      c.deployModel(new TextEncoder().encode('m'), {
        name: 'm',
        modelType: 'onnx',
        accessType: 'public',
        accessPrice: 0n,
        encrypted: false,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any),
    ).rejects.toThrow(WrongNetworkError);
    expect(sent).toEqual([]);
  });

  it('a failed check is not cached: once the node reports r1006, the next call re-reads block 0 and passes', async () => {
    const { c } = client(R1006_GENESIS);
    const node = switchingDouble([R1005_GENESIS, R1006_GENESIS]);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any).provider = node.p;
    await expect(c.verifyNetwork()).rejects.toThrow(WrongNetworkError);
    await expect(c.verifyNetwork()).resolves.toBeUndefined();
    expect(node.reads()).toBe(2);
    // ...and a success is cached.
    await expect(c.verifyNetwork()).resolves.toBeUndefined();
    expect(node.reads()).toBe(2);
  });

  it('deployModel refuses before any transaction leaves on the wrong network', async () => {
    const { c, sent } = client(R1005_GENESIS);
    await expect(
      c.deployModel(new TextEncoder().encode('m'), {
        name: 'm',
        modelType: 'onnx',
        accessType: 'public',
        accessPrice: 0n,
        encrypted: false,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any),
    ).rejects.toThrow(WrongNetworkError);
    expect(sent).toEqual([]);
  });

  it('inference refuses before any transaction leaves on the wrong network', async () => {
    const { c, sent } = client(R1005_GENESIS);
    await expect(
      c.inference({ modelId: '0x' + 'ab'.repeat(32), inputData: { x: 1 } }),
    ).rejects.toThrow(WrongNetworkError);
    expect(sent).toEqual([]);
  });

  it('expectedGenesisHash: null opts out (a dev chain), an explicit hash overrides', async () => {
    const off = client(R1005_GENESIS, { expectedGenesisHash: null });
    await expect(off.c.verifyNetwork()).resolves.toBeUndefined();
    expect(off.calls).toEqual([]);
    const pinned = client(R1005_GENESIS, { expectedGenesisHash: R1005_GENESIS });
    await expect(pinned.c.verifyNetwork()).resolves.toBeUndefined();
  });

  it('rejects a malformed expectedGenesisHash at construction', () => {
    expect(
      () => new CitrateClient({ rpcUrl: 'http://127.0.0.1:8545', expectedGenesisHash: '0x1234' }),
    ).toThrow(/expectedGenesisHash/);
  });
});

describe('verifyWalletAddressOnChain checks the genesis of the book it verifies against', () => {
  const UID = '0x' + '42'.repeat(32);
  function provider(genesis: string) {
    const local = predictWalletAddress(UID);
    return chainDouble(genesis, {
      getNetwork: async () => ({ chainId: 40204n }),
      getCode: async () => '0x6080',
      call: async () => AbiCoder.defaultAbiCoder().encode(['address'], [getAddress(local)]),
    });
  }

  it('refuses an r1005 node even though its chain id is 40204', async () => {
    const { p } = provider(R1005_GENESIS);
    await expect(verifyWalletAddressOnChain(UID, p as unknown as Provider)).rejects.toThrow(WrongNetworkError);
  });

  it('verifies on the r1006 genesis', async () => {
    const { p } = provider(R1006_GENESIS);
    await expect(verifyWalletAddressOnChain(UID, p as unknown as Provider)).resolves.toBe(predictWalletAddress(UID));
  });
});

describe('ComputeRefunds checks the genesis before using book addresses', () => {
  const word = (v: bigint) => '0x' + v.toString(16).padStart(64, '0');
  function runner(genesis: string | null, viaProvider = false) {
    const calls: string[] = [];
    const block = { getBlock: async () => (genesis === null ? null : { hash: genesis }) };
    return {
      calls,
      r: {
        async call() {
          calls.push('call');
          return word(5n);
        },
        async sendTransaction() {
          calls.push('send');
          return {};
        },
        async getAddress() {
          return '0x' + 'ab'.repeat(20);
        },
        ...(viaProvider ? { provider: block } : block),
      },
    };
  }

  it('refuses views and claims on an r1005 node before any eth_call', async () => {
    const { r, calls } = runner(R1005_GENESIS);
    const c = new ComputeRefunds(r);
    await expect(c.refundOwed('0x' + 'ab'.repeat(20))).rejects.toThrow(WrongNetworkError);
    await expect(c.claimNativeRefund()).rejects.toThrow(WrongNetworkError);
    expect(calls).toEqual([]);
  });

  it('works on r1006, reading block 0 through a signer provider too', async () => {
    const { r } = runner(R1006_GENESIS, true);
    const c = new ComputeRefunds(r);
    await expect(c.refundOwed('0x' + 'ab'.repeat(20))).resolves.toBe(5n);
  });

  it('fails closed when block 0 cannot be read, before any eth_call', async () => {
    const { r, calls } = runner(R1006_GENESIS);
    const c = new ComputeRefunds({
      ...r,
      getBlock: async () => {
        throw new Error('connection reset');
      },
    });
    await expect(c.refundOwed('0x' + 'ab'.repeat(20))).rejects.toThrow(WrongNetworkError);
    await expect(c.claimNativeRefund()).rejects.toThrow(WrongNetworkError);
    expect(calls).toEqual([]);
  });

  it('a failed check is not cached: the next call re-reads block 0 and, on r1006, proceeds', async () => {
    const { r, calls } = runner(R1006_GENESIS);
    const node = switchingDouble([R1005_GENESIS, R1006_GENESIS]);
    const c = new ComputeRefunds({ ...r, getBlock: node.p.getBlock });
    await expect(c.refundOwed('0x' + 'ab'.repeat(20))).rejects.toThrow(WrongNetworkError);
    expect(calls).toEqual([]);
    await expect(c.refundOwed('0x' + 'ab'.repeat(20))).resolves.toBe(5n);
    expect(node.reads()).toBe(2);
    await expect(c.refundOwed('0x' + 'ab'.repeat(20))).resolves.toBe(5n);
    expect(node.reads()).toBe(2);
  });

  it('refuses book addresses when the runner cannot report block 0', async () => {
    const c = new ComputeRefunds({ call: async () => word(1n) });
    await expect(c.refundOwed('0x' + 'ab'.repeat(20))).rejects.toThrow(/cannot verify|block 0/);
  });

  it('skips the check when every address is supplied by the caller', async () => {
    const c = new ComputeRefunds(
      { call: async () => word(7n) },
      {
        computeMarketplace: '0x' + '11'.repeat(20),
        inferenceRouter: '0x' + '22'.repeat(20),
        computePoolTraining: '0x' + '33'.repeat(20),
      },
    );
    await expect(c.refundOwed('0x' + 'ab'.repeat(20))).resolves.toBe(7n);
  });
});
