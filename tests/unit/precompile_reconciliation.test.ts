/**
 * DEVX-S3 — precompile reconciliation report (test form).
 *
 * Documents where the legacy PRECOMPILE_ADDRESSES map agrees with the canonical artifact table
 * (PRECOMPILES) and where it does not. This is not a "fix" — precompile addresses are
 * consensus-level, so the actual correction is chain-team-gated. This test is the evidence.
 */
import { PRECOMPILES, PRECOMPILE_ADDRESSES } from '../../src/utils/constants';

describe('precompile reconciliation vs the canonical artifact table', () => {
  it('legacy INFERENCE_* deploy/run/batch/metadata/benchmark/encrypt match the canonical table', () => {
    expect(PRECOMPILE_ADDRESSES.INFERENCE_DEPLOY).toBe(PRECOMPILES.ModelDeploy);
    expect(PRECOMPILE_ADDRESSES.INFERENCE_RUN).toBe(PRECOMPILES.ModelInference);
    expect(PRECOMPILE_ADDRESSES.INFERENCE_BATCH).toBe(PRECOMPILES.BatchInference);
    expect(PRECOMPILE_ADDRESSES.INFERENCE_METADATA).toBe(PRECOMPILES.ModelMetadata);
    expect(PRECOMPILE_ADDRESSES.INFERENCE_BENCHMARK).toBe(PRECOMPILES.ModelBenchmark);
    expect(PRECOMPILE_ADDRESSES.INFERENCE_ENCRYPT).toBe(PRECOMPILES.ModelEncryption);
  });

  it('DISCREPANCY: legacy INFERENCE_VERIFY (0x…0104) is NOT in the canonical table', () => {
    // The canonical proof-verify precompile is InferenceProofVerify at 0x…0108.
    expect(PRECOMPILE_ADDRESSES.INFERENCE_VERIFY).toBe('0x0000000000000000000000000000000000000104');
    expect(Object.values(PRECOMPILES)).not.toContain(PRECOMPILE_ADDRESSES.INFERENCE_VERIFY);
    expect(PRECOMPILES.InferenceProofVerify).toBe('0x0000000000000000000000000000000000000108');
  });

  it('DISCREPANCY: legacy 0x1000-range state precompiles are NOT enumerated in the canonical table', () => {
    for (const addr of [PRECOMPILE_ADDRESSES.MODEL, PRECOMPILE_ADDRESSES.ARTIFACT, PRECOMPILE_ADDRESSES.GOVERNANCE]) {
      expect(Object.values(PRECOMPILES)).not.toContain(addr);
    }
  });

  it('the canonical table carries the tensor + x402 precompiles the legacy map lacked', () => {
    expect(PRECOMPILES.Ed25519Verify).toBe('0x0000000000000000000000000000000000000120');
    expect(PRECOMPILES.X402Eip712Verify).toBe('0x0000000000000000000000000000000000000200');
  });
});
