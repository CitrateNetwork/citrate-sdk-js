# Changelog

All notable changes to `@citratelabs/sdk` are documented here. This project
follows [Semantic Versioning](https://semver.org/); while it is 0.x, a patch
release may carry breaking changes when a security fix requires them.

## [0.2.4] - 2026-09-25 — Hardening

### Changed

- `deployModel` serialises the transaction payload once, runs the key-share
  guard on the parsed form of those exact bytes, and sends the same bytes.

### Tests

- A differential property test runs the share guard against the strict
  `hexToBytes` parser and other known hex decoders over generated near-hex
  input.

### Compatibility shim

- `@citratelabs/citrate-js` 0.2.4 re-exports `@citratelabs/sdk` 0.2.4.

## [0.2.3] - 2026-09-25 — Pre-bounty audit remediation (SECURITY)

> **Security advisory: upgrade from 0.2.0 – 0.2.2.**
> `CitrateClient.deployModel` with `encrypted: true` and
> `encryptionConfig.thresholdShares > 0` wrote **every Shamir share of the model
> AES key** into the public `INFERENCE_DEPLOY` calldata
> (`metadata.encryption.keyShares`). Anyone reading the chain could rebuild the
> key and decrypt the model with no private key (PBA-L4-001, CRITICAL).
> Models deployed that way should be treated as disclosed: re-encrypt under a
> new key and redeploy. Deploys with `thresholdShares: 0` or no
> `encryptionConfig` were not affected. 0.2.0 – 0.2.2 are to be deprecated on
> npm with a GHSA (owner action).

### Security

- **PBA-L4-001 (CRITICAL):** key shares never enter deploy metadata or
  calldata. `thresholdShares > 0` now requires
  `encryptionConfig.shareHolderPublicKeys` (one distinct secp256k1 public key
  per share); each share is ECDH-wrapped to its holder (V2 envelope) and
  returned as `ModelDeployment.keyShareEnvelopes` / `EncryptedModelResult
  .keyShareEnvelopes` for **off-chain** delivery. Holders open theirs with
  `KeyManager.unwrapKeyShare(envelope, ownerPublicKey)`. `deployModel` refuses
  any payload carrying a key-share field. Tripwires decode the deploy calldata
  and assert no subset rebuilds the key, in the unit tests and against the
  `npm pack` tarball in CI and in the release workflow.
- **PBA-L4-005:** Shamir reconstruction validates every share (integer x in
  1..255, distinct, equal non-empty y), takes the threshold from the caller,
  and `verifyShares` checks that extra shares lie on the polynomial.
- **PBA-L3a-011:** `verifyIdToken` requires `exp` (and `iat`, and a `typ` of
  `JWT` or none, in parity with the Python SDK's PBA-L6b-029 fix).
- **PBA-L6b-027 (variant):** `verifyWalletAddressOnChain` asserts the provider's
  chain id and that the factory has code before trusting it.

- **Verifier follow-ups (still 0.2.3, unreleased):**
  - `thresholdShares: NaN` (or any non-integer) raises instead of silently
    disabling sharing.
  - `thresholdShares: 1` requires `allowSingleHolderRecovery: true`.
  - The deploy guard also refuses values shaped like shares (`{x, y}` or a
    wrapped share record), including inside JSON strings.
  - `verifyIdToken` refuses an `iat` more than the clock tolerance in the
    future.
  - The holder dedupe is pinned by a compressed/uncompressed test.
  - Note: the share envelope is the existing static-static ECDH V2 scheme,
    bound to both keys through HKDF info. It does not use a per-share
    ephemeral key.

- **Round 3 (still 0.2.3, unreleased):** the share guard matches only
  share-shaped values (x in 1..255 and a y of at least 16 bytes), so
  coordinate-like caller metadata such as `{x: 1, y: "10"}` is no longer
  refused.

### Changed (breaking)

- `IdentityClient.refresh(refreshToken, expectedSub)`: `expectedSub` is
  required; a refreshed token naming another `sub` is refused (PBA-L3a-011).
- SIWE now matches citrate-identity (PBA-L3a-012): `siweChallenge()` is a GET
  returning `{ nonce }`; build the message with `identity.buildSiweMessage(...)`;
  `siweVerify` returns `{ kind: 'redirect', redirectTo }` or
  `{ kind: 'token', idToken, claims }`. The old client POSTed to a GET-only
  route and expected tokens the server never returned, so it never worked.
- `KeyManager.reconstructKeyFromShares(shares, threshold)`: threshold is
  required.
- `CHAIN_IDS.MAINNET` (= 1, Ethereum mainnet's id) is removed (PBA-L8-016).
  Citrate runs on 40204 only.

### Compatibility shim

- `@citratelabs/citrate-js` 0.2.3 re-exports `@citratelabs/sdk` 0.2.3.
