// citrate-js/src/types/attestation.ts
//
// RM-M3 WP-M3.8 — TypeScript SDK surface for the attestation gate.
//
// **Phase 1 (current):** these types describe the public-API
// shape that Phase 2 will populate. The Phase 1 default gate
// (`AlwaysReject`) gives every caller a structured rejection;
// the SDK surfaces this via `inferenceError.attestationGate`.
//
// **Phase 2 (future, blocked on CM-08 hardware):** the SDK
// will gain `attestation.fetchRegistry()` to read MAA + NRAS
// public keys from the on-chain registry, and a helper to
// build the wire-format attestation blob that prefixes the
// inference input.

/**
 * Identifies which attestation gate the validator is running.
 * `AlwaysReject` is the Phase 1 default; production validators
 * upgrade to `MaaPlusNras` after CM-08.
 */
export type AttestationGateName =
  | 'AlwaysReject'
  | 'MaaPlusNras'
  | (string & {}); // open-ended: future gate impls

/**
 * Result returned by the validator when 0x0101 / 0x0102 is
 * called and the attestation gate denies the request. Surfaced
 * via the SDK's `InferenceError`.
 */
export interface AttestationRejection {
  /** Which gate impl produced the rejection. */
  gate: AttestationGateName;
  /** Human-readable reason (e.g., "Phase 1: TEE attestation
   *  gate denies inference."). */
  reason: string;
  /** True if the gate would never allow this input regardless
   *  of context (i.e., the gate is `AlwaysReject`). */
  unconditional: boolean;
}

/**
 * Phase 2: the wire-format prefix that goes ahead of the
 * inference payload when calling 0x0101 with a valid
 * attestation. Phase 1 callers ignore this — every call
 * gets rejected anyway.
 */
export interface AttestationBlob {
  /** Microsoft Azure Attestation (MAA) JWT, base64-encoded. */
  maaJwt: string;
  /** NVIDIA Remote Attestation Service (NRAS) signed claim. */
  nrasClaim: string;
  /** Provider address that this attestation establishes as
   *  the attested origin. */
  attestedProvider: string;
}

/**
 * Phase 2 helper: parse a precompile error message into the
 * structured rejection record.
 *
 * Pattern: "C-01 / RM-M3: ... gated by attestation. Gate
 * \`<name>\` says: <reason>"
 */
export function parseAttestationRejection(
  errorMessage: string,
): AttestationRejection | null {
  const match = errorMessage.match(
    /Gate `([^`]+)` says: (.+)$/,
  );
  if (!match) return null;
  const [, gate, reason] = match;
  if (!gate || !reason) return null;
  return {
    gate: gate as AttestationGateName,
    reason: reason.trim(),
    unconditional: gate === 'AlwaysReject',
  };
}
