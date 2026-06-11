---
created: 2026-06-11
branch: audit/secrem02-batch-encryption
author: Fable 5 (Claude Code) subagent
sprint: SECREM-02-followup-remediation
repo: citrate-sdk-js
baseline_test_count: 19
---

# SECREM-02 5.4 — follow-up remediation log (client layer)

Source findings:
- `citrate-security/audits/2026-06-09-federation-followup-security-audit/per-repo/citrate-sdk-js/REPORT.md` (FUA-SDK-JS-01)
- `citrate-security/audits/2026-06-09-federation-followup-security-audit/07_KNOWN_AND_IN_REMEDIATION.md` (sdk-js client-layer residuals `CITRATE_SDK_JS-2026-05-31-003` / `-004`, both HIGH)

Baseline suite: 4 suites / **19 tests** green at branch point (`f2aa93f`).
Final suite: 5 suites / **33 tests** green (`npm test`; `tsc --noEmit` clean on both build and test configs).

| Finding | Sev | Red test(s) (tests/unit/secrem02_client_layer.test.ts) | Fix (file) | Suite | Mutation | Disposition |
|---|---|---|---|---|---|---|
| FUA-SDK-JS-01 — `batchInference` silently drops encryption (plaintext batch inputs on public calldata) | MED | "never puts plaintext batch inputs on calldata…", "fails closed before any tx when encrypted is set without a recipient key", "single-call inference fails closed… when no KeyManager", "deployModel fails closed (no plaintext upload)…" — all 4 RED pre-fix | `src/types/Inference.ts` (BatchInferenceRequest gains `encrypted?`/`recipientPublicKey?`); `src/client/CitrateClient.ts` `batchInference` (fail-closed up-front guard + per-input threading into `inference()`), `inference()` + `deployModel()` (encryption-requested-but-unavailable now throws instead of silent plaintext downgrade) | 33/33 green | M1 (remove threading) → 1 test fails; M2 (remove up-front guard) → 1 fails; M3 (restore `encrypted && keyManager` downgrade in `inference`) → 1 fails; M4 (same in `deployModel`) → 1 fails. All restored. | FIXED |
| CITRATE_SDK_JS-2026-05-31-003 — validation layer is dead code | HIGH | "constructor rejects a non-http(s)/ws(s) RPC URL", "constructor rejects a malformed private key", "deployModel rejects invalid config…", "deployModel rejects empty model data…", "inference rejects a malformed modelId…", "batchInference validates inputs up front…" — all 6 RED pre-fix | `src/client/CitrateClient.ts`: constructor wires `validateRpcUrl`/`validatePrivateKey`; `deployModel` wires `validateModelData`+`validateModelConfig`; `inference` wires `validateInferenceRequest`; `batchInference` validates every input before the first tx | 33/33 green | M5 (remove constructor validators) → 2 tests fail; M6 (remove deploy/inference/batch validator calls) → 4 fail. Restored. | FIXED (re-verified STILL-OPEN at branch point: grep for validator names in `src/client` had 0 hits pre-fix) |
| CITRATE_SDK_JS-2026-05-31-004 — `purchaseModelAccess` pays `0x..0104` (INFERENCE_VERIFY); hardcoded precompile literals | HIGH | "purchaseModelAccess fails closed instead of routing value to the verify precompile", "deployModel routes to the canonical INFERENCE_DEPLOY precompile", "inference routes to the canonical INFERENCE_RUN precompile", "tripwire: no hardcoded precompile address literals" — all 4 RED pre-fix | `src/client/CitrateClient.ts`: `purchaseModelAccess` now throws `CitrateError` (fail-closed, money never moves); `deployModel`/`inference` route via `PRECOMPILE_ADDRESSES.INFERENCE_DEPLOY`/`.INFERENCE_RUN` from `src/utils/constants.ts`; all `to: '0x01…'` literals deleted | 33/33 green | M7 (restore value-bearing send to INFERENCE_VERIFY) → 1 test fails; M8 (restore hardcoded `0x0100…01xx` literals) → 3 fail. Restored. | FIXED (fail-closed disable; see note) |

## Notes

- **-004 ground truth (why a fail-closed disable, not an address swap):** the node
  (`citrate-chain/core/execution/src/precompiles/inference.rs addresses::*` and
  `executor.rs model/artifact/governance precompiles at 0x..1000/1002/1003`) defines
  **no access-purchase precompile anywhere**. `0x..0104` is `PROOF_VERIFY`
  (= constants `INFERENCE_VERIFY`). Additionally the client's old hardcoded literals
  (`0x0100…01xx`, leading byte `0x01`) match **no** node dispatch address at all.
  There is therefore no correct address to point the payment at; the only safe
  client-side remediation is to refuse to move buyer funds until the node ships a
  node-confirmed access-purchase operation. `purchaseModelAccess` now throws with an
  explanatory `CitrateError` referencing this finding. This is an intentional
  breaking change for a money path that previously burned/misrouted funds.
- **Routing correction:** `deployModel` and `inference` previously sent to
  `0x0100…0100`/`0x0100…0101` (nonexistent addresses). They now use the canonical
  `PRECOMPILE_ADDRESSES.INFERENCE_DEPLOY` (`0x0000…0100`) and `INFERENCE_RUN`
  (`0x0000…0101`), matching the node's `MODEL_DEPLOY`/`MODEL_INFERENCE` table. A
  source tripwire test forbids reintroducing `to: '0x01…'` literals in the client.
- **FUA-SDK-JS-01 scope:** beyond threading encryption through the batch path, the
  same "configured-but-unapplied encryption" silent-downgrade landmine existed in
  `inference()` (`request.encrypted && this.keyManager`) and `deployModel()`
  (`config.encrypted && this.keyManager`); both now fail closed. `encryptData`
  already fails closed without `recipientPublicKey` (RM-G.3), and `batchInference`
  additionally pre-checks the recipient key before any tx so the error cannot be
  swallowed into the per-input `errors[]` array.
- **Mutation protocol:** 8 mutations applied one at a time (M1–M8 above), each
  confirmed to fail at least one of the 14 new tests, each restored; full suite
  re-run green (33/33) after restoration.
- **Out of scope / still open (not touched, per WP boundary):** -006 parallel nonce
  reuse, -007 WS stream IDs, -008 event-topic parse, -009 receipt schema, -010
  `hexToBytes`, FUA-SDK-JS-02/-03/-04, WEB-5 npm scoping, version-string drift.
- Repo hygiene: added `.gitignore` (`node_modules/`, `dist/`, `.DS_Store`, logs,
  coverage) — the repo previously had none; untracked `.DS_Store` files left
  untracked/uncommitted.
