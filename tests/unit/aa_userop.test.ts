/**
 * EW-S1 WP-7 — UserOperation packing + hashing + Kernel encodings.
 *
 * Hash vector source (no mocks): the LIVE EntryPoint v0.7 on chain 40204, sourced
 * from the federation contract artifact (AA_ADDRESSES.EntryPoint =
 * 0x97d5391a647429233e202f99231743c53a648f3c). Re-earned 2026-09-23 (rpc.citrate.ai) after
 * the 2026-09-20 state re-roll retired the prior EntryPoint (0xc698feaf…, now empty code) —
 * the EntryPoint address is committed to the hash domain, so the vector moves with the
 * artifact, never a hand-pinned constant. Re-verified via:
 *   cast call $EP 'getUserOpHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes))' \
 *     '(0x5cE3…,0,0x,0xdeadbeef,0x…0186a0,50000,0x…77359400,0x,0x)' --rpc-url https://rpc.citrate.ai
 * Encoding layouts are pinned to the vendored Kernel v3.3 + CitratePaymaster sources.
 */

import { AbiCoder } from 'ethers';

import {
  buildPackedUserOp,
  encodeDeployFor,
  getUserOpHash,
  packAccountGasLimits,
  packCitratePaymasterAndData,
  packGasFees,
  packInitCode,
  toRpcUserOperation,
  UserOpError,
} from '../../src/aa/userop';
import {
  composeNonce,
  encodeExecuteBatch,
  encodeExecuteSingle,
  EXECUTE_SELECTOR,
  kernelInitializeCalldata,
  packValidationId,
  validatorNonceKey,
  webauthnInstallData,
  ecdsaInstallData,
  guardianInstallData,
  EcdsaValidatorSource,
  KernelEncodingError,
} from '../../src/aa/kernel';
import { PaymasterCategory } from '../../src/aa/types';
import { AA_ADDRESSES, CHAIN_IDS } from '../../src/utils/constants';

const coder = AbiCoder.defaultAbiCoder();

// Sourced from the federation contract artifact — never hand-pinned (DEVX-S0).
const ENTRY_POINT = AA_ADDRESSES.EntryPoint;
const CHAIN_ID = BigInt(CHAIN_IDS.TESTNET);
const SENDER = '0x5cE327300221659b66323dC344C2275A7DA756fF' as const;

describe('gas packing', () => {
  it('packs accountGasLimits as verification ++ call', () => {
    expect(packAccountGasLimits(150_000n, 100_000n)).toBe(
      '0x000000000000000000000000000249f0000000000000000000000000000186a0',
    );
  });

  it('packs gasFees as maxPriority ++ maxFee', () => {
    expect(packGasFees(1_000_000_000n, 2_000_000_000n)).toBe(
      '0x0000000000000000000000003b9aca0000000000000000000000000077359400',
    );
  });

  it('rejects values over 128 bits', () => {
    expect(() => packAccountGasLimits(1n << 128n, 0n)).toThrow(UserOpError);
  });
});

describe('getUserOpHash — parity with the LIVE EntryPoint v0.7 on 40204', () => {
  it('matches the on-chain hash for the pinned vector', () => {
    const op = buildPackedUserOp({
      sender: SENDER,
      nonce: 0n,
      callData: '0xdeadbeef',
      callGasLimit: 100_000n,
      verificationGasLimit: 150_000n,
      preVerificationGas: 50_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      maxFeePerGas: 2_000_000_000n,
    });
    // Re-earned 2026-09-23 vs live EntryPoint 0x97d5391a… on 40204 (see header).
    expect(getUserOpHash(op, ENTRY_POINT, CHAIN_ID)).toBe(
      '0x1dd682cbe3426e879e981f22c131e8b18458f7d2b3157dce728ef48ca8cf6140',
    );
  });

  it('changes when any committed field changes', () => {
    const base = buildPackedUserOp({
      sender: SENDER,
      nonce: 0n,
      callData: '0xdeadbeef',
      callGasLimit: 100_000n,
      verificationGasLimit: 150_000n,
      preVerificationGas: 50_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      maxFeePerGas: 2_000_000_000n,
    });
    const h = getUserOpHash(base, ENTRY_POINT, CHAIN_ID);
    expect(getUserOpHash({ ...base, nonce: 1n }, ENTRY_POINT, CHAIN_ID)).not.toBe(h);
    expect(
      getUserOpHash({ ...base, callData: '0xdeadbeee' }, ENTRY_POINT, CHAIN_ID),
    ).not.toBe(h);
    expect(getUserOpHash(base, ENTRY_POINT, 1n)).not.toBe(h);
  });
});

describe('CitratePaymaster paymasterAndData', () => {
  it('puts the category byte at offset 52 (PMD_TAG_OFFSET)', () => {
    const pmd = packCitratePaymasterAndData({
      paymaster: '0x96bb6ca3b6a3e2e08a3557dfab6c7a29eb048373',
      paymasterVerificationGasLimit: 60_000n,
      paymasterPostOpGasLimit: 40_000n,
      category: PaymasterCategory.FirstOp,
    });
    // 20 + 16 + 16 = 52 bytes before the tag.
    expect(pmd.length).toBe(2 + 53 * 2);
    const categoryByte = pmd.slice(2 + 52 * 2, 2 + 53 * 2);
    expect(categoryByte).toBe('02');
  });
});

describe('Kernel nonce keys', () => {
  it('routes to an installed validator via 0x00|0x01|address|key', () => {
    const validator = '0x42F3d7842d382D47199533a6BFcceAF483C6C857';
    const key = validatorNonceKey(validator, 0);
    const hex = key.toString(16).padStart(48, '0');
    expect(hex).toBe(`0001${validator.slice(2).toLowerCase()}0000`);
  });

  it('composes a full 256-bit nonce from key + sequence', () => {
    const key = validatorNonceKey('0x42F3d7842d382D47199533a6BFcceAF483C6C857');
    const nonce = composeNonce(key, 7n);
    expect(nonce & 0xffffffffffffffffn).toBe(7n);
    expect(nonce >> 64n).toBe(key);
  });

  it('rejects out-of-range parts', () => {
    expect(() => composeNonce(1n << 192n, 0n)).toThrow(KernelEncodingError);
    expect(() => composeNonce(0n, 1n << 64n)).toThrow(KernelEncodingError);
  });
});

describe('execute() encoding', () => {
  it('single: selector + mode word + packed target/value/data', () => {
    const callData = encodeExecuteSingle({
      to: '0x000000000000000000000000000000000000dEaD',
      value: 1n,
      data: '0xabcdef',
    });
    expect(callData.startsWith(EXECUTE_SELECTOR)).toBe(true);
    const [mode, exec] = coder.decode(
      ['bytes32', 'bytes'],
      '0x' + callData.slice(10),
    );
    expect(mode).toBe(
      '0x0000000000000000000000000000000000000000000000000000000000000000',
    );
    // packed: 20-byte target ++ 32-byte value ++ data
    expect(exec).toBe(
      '0x000000000000000000000000000000000000dead' +
        '0000000000000000000000000000000000000000000000000000000000000001' +
        'abcdef',
    );
  });

  it('batch: callType 0x01 + ABI-encoded executions', () => {
    const callData = encodeExecuteBatch([
      { to: '0x000000000000000000000000000000000000dEaD', value: 0n, data: '0x01' },
      { to: '0x000000000000000000000000000000000000bEEF', value: 2n, data: '0x02' },
    ]);
    const [mode, exec] = coder.decode(
      ['bytes32', 'bytes'],
      '0x' + callData.slice(10),
    );
    expect(mode).toBe(
      '0x0100000000000000000000000000000000000000000000000000000000000000',
    );
    const [decoded] = coder.decode(['tuple(address,uint256,bytes)[]'], exec);
    expect(decoded.length).toBe(2);
    expect(decoded[1][1]).toBe(2n);
  });

  it('rejects an empty batch', () => {
    expect(() => encodeExecuteBatch([])).toThrow(KernelEncodingError);
  });
});

describe('install-data packers (parity with identity + wallet-aa layouts)', () => {
  it('webauthn: 97 bytes, uv flag last', () => {
    const data = webauthnInstallData({
      credentialIdHash: ('0x' + 'de'.repeat(32)) as `0x${string}`,
      x: ('0x' + 'aa'.repeat(32)) as `0x${string}`,
      y: ('0x' + 'bb'.repeat(32)) as `0x${string}`,
      requireUserVerification: true,
    });
    expect(data.length).toBe(2 + 97 * 2);
    expect(data.endsWith('01')).toBe(true);
  });

  it('ecdsa: 21 bytes, owner ++ source', () => {
    const data = ecdsaInstallData({
      owner: '0x1212121212121212121212121212121212121212',
      source: EcdsaValidatorSource.GuiNative,
    });
    expect(data).toBe('0x121212121212121212121212121212121212121201');
  });

  it('guardians: threshold ++ count ++ addresses, bounds enforced', () => {
    const g1 = '0x0101010101010101010101010101010101010101' as const;
    const g2 = '0x0202020202020202020202020202020202020202' as const;
    const data = guardianInstallData({ threshold: 2, guardians: [g1, g2] });
    expect(data).toBe('0x0202' + g1.slice(2) + g2.slice(2));
    expect(() => guardianInstallData({ threshold: 1, guardians: [g1] })).toThrow(
      KernelEncodingError,
    );
    expect(() =>
      guardianInstallData({ threshold: 3, guardians: [g1, g2] }),
    ).toThrow(KernelEncodingError);
    expect(() =>
      guardianInstallData({ threshold: 1, guardians: [g1, g1] }),
    ).toThrow(KernelEncodingError);
  });

  it('initialize calldata: selector + bytes21 root validator', () => {
    const validator = '0x97ff6d1c4d2f4337ec09f2a1c01808016f728def';
    const calldata = kernelInitializeCalldata({
      rootValidator: validator,
      validatorData: '0xaabbcc',
    });
    // initialize(bytes21,address,bytes,bytes,bytes[]) selector
    expect(calldata.slice(0, 10)).toBe('0x3c3b752b');
    expect(packValidationId(0x01, validator)).toBe(
      ('0x01' + validator.slice(2)) as string,
    );
  });
});

describe('initCode + deployFor + RPC conversion round-trip', () => {
  it('splits factory/factoryData and paymaster fields for the bundler wire', () => {
    const factory = '0xd951Cb15495cb6541F7541b9194B2D311E12FD57' as const;
    const factoryData = encodeDeployFor({
      userId: ('0x' + '11'.repeat(32)) as `0x${string}`,
      initialValidator: '0x97ff6d1c4d2f4337ec09f2a1c01808016f728def',
      initData: '0xdef3e4f4',
      expiresAt: 1_780_000_000n,
      signature: ('0x' + '22'.repeat(65)) as `0x${string}`,
    });
    const op = buildPackedUserOp({
      sender: SENDER,
      nonce: composeNonce(0n, 3n),
      initCode: packInitCode(factory, factoryData),
      callData: '0xdeadbeef',
      callGasLimit: 100_000n,
      verificationGasLimit: 150_000n,
      preVerificationGas: 50_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      maxFeePerGas: 2_000_000_000n,
      paymasterAndData: packCitratePaymasterAndData({
        paymaster: '0x96bb6ca3b6a3e2e08a3557dfab6c7a29eb048373',
        paymasterVerificationGasLimit: 60_000n,
        paymasterPostOpGasLimit: 40_000n,
        category: PaymasterCategory.Standard,
      }),
    });

    const rpc = toRpcUserOperation(op);
    expect(rpc.factory?.toLowerCase()).toBe(factory.toLowerCase());
    expect(rpc.factoryData).toBe(factoryData);
    expect(rpc.callGasLimit).toBe('0x0186a0');
    expect(rpc.verificationGasLimit).toBe('0x0249f0');
    expect(rpc.maxPriorityFeePerGas).toBe('0x3b9aca00');
    expect(rpc.maxFeePerGas).toBe('0x77359400');
    expect(rpc.paymaster?.toLowerCase()).toBe(
      '0x96bb6ca3b6a3e2e08a3557dfab6c7a29eb048373',
    );
    expect(rpc.paymasterData).toBe('0x00');
    expect(rpc.nonce).toBe('0x03');
  });
});
