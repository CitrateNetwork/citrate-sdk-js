# @citratelabs/sdk

The TypeScript/JavaScript SDK for the [Citrate Network](https://citrate.ai), an AI-native Layer-1 BlockDAG (chain id **40204**, native token **SALT**). One package covers the whole developer surface: chain reads and signed transactions, on-chain model deployment and inference, the OpenAI-compatible inference gateway, Citrate identity (OIDC + SIWE), the ERC-4337 embedded smart wallet, entitlements, and agent memory.

Works in Node.js (≥ 16; 20 LTS recommended) and the browser. Ships ESM, CommonJS and type declarations.

```bash
npm install @citratelabs/sdk
```

## Quickstart

```ts
import { CitrateClient, DEFAULT_RPC_URLS, CHAIN_IDS } from '@citratelabs/sdk';

const client = new CitrateClient({
  rpcUrl: DEFAULT_RPC_URLS[CHAIN_IDS.TESTNET],   // ['https://rpc.citrate.ai']
  privateKey: process.env.CITRATE_PRIVATE_KEY,     // optional; needed only to sign
});

console.log(await client.getChainId());            // 40204
console.log(await client.getBalance());            // bigint, in wei (SALT has 18 decimals)
```

If `getChainId()` returns `40204`, you are connected.

## What the SDK covers

| Area | Import | Use it to |
|---|---|---|
| Chain client | `CitrateClient` | Read chain state, sign and send transactions, deploy models, run on-chain inference |
| Streaming | `WebSocketClient` | Stream inference results and subscribe to model / marketplace events |
| Inference gateway | `gateway.GatewayClient` | Call hosted models through an OpenAI-compatible API (`/v1/chat/completions`) |
| Identity | `identity.*` | Sign users in with OIDC (PKCE) or Sign-In with Ethereum, verify ID tokens, predict a user's wallet address |
| Embedded wallet | `aa.*` | Build, sign (passkey or EOA) and submit ERC-4337 user operations for a user's smart account |
| Entitlements | `entitlements.*` | Turn an identity claim into capabilities (`can(claim, 'gatewayKeys')`) |
| Memory | `memory.*` | Read and write agent memory on a citrate-memories gateway (REST or MCP) |
| Crypto | `KeyManager`, `CryptoManager`, `ShamirSecretSharing` | Keys, signing, ECDH encryption, hashing, secret sharing |
| React | `@citratelabs/sdk/react/hooks` | `useCitrateClient`, `useInference`, `useModelDeployment`, `useModelInfo`, `useModelList` |
| Network constants | `CHAIN_IDS`, `DEFAULT_RPC_URLS`, `AA_ADDRESSES`, `CONTRACT_ADDRESSES`, `PRECOMPILES`, … | Canonical addresses and endpoints (never hardcode them) |

Namespaced modules are imported as a group:

```ts
import { gateway, identity, aa, entitlements, memory } from '@citratelabs/sdk';
```

## Guides

### Connecting to the chain

```ts
const client = new CitrateClient({
  rpcUrl: ['https://rpc.citrate.ai', 'https://rpc-backup.example'], // array = automatic failover
  privateKey: process.env.CITRATE_PRIVATE_KEY,
  timeout: 30_000,
  retries: 3,
});
```

- **Failover.** Pass several RPC URLs and the client moves to the next one on a transport error (DNS, refused connection, timeout). A JSON-RPC error from a reachable node is a real answer and is returned, not retried.
- **Transport security.** Remote `http://` and `ws://` endpoints are refused, because signed transactions and keys would travel in cleartext. Loopback (`localhost`, `127.0.0.1`) is always allowed. Set `allowInsecureHttp: true` only for a trusted internal network without TLS.
- **Without a private key** the client is read-only. Signing methods throw a `CitrateError`.

Read methods: `getChainId()`, `getBalance(address?)`, `getNonce(address?)`, `getAddress()`, `getRpcUrls()`.

### Models and on-chain inference

Model operations go through the chain's AI precompiles and require a signer.

```ts
import { CitrateClient, ModelType, AccessType } from '@citratelabs/sdk';

const deployment = await client.deployModel(modelBytes, {
  name: 'sentiment-v1',
  modelType: ModelType.ONNX,
  accessType: AccessType.PAID,
  accessPrice: 10n ** 15n,   // wei per inference
  encrypted: false,
});

const result = await client.inference({
  modelId: deployment.modelId,
  inputData: { text: 'Citrate is fast' },
});
console.log(result.outputData, result.txHash, result.gasUsed);
```

| Method | What it does |
|---|---|
| `deployModel(bytes, config)` | Hashes the model, optionally encrypts it, uploads it (IPFS if `ipfsApiUrl` is set, otherwise records the content hash), and sends a deploy transaction to the `INFERENCE_DEPLOY` precompile. Returns `modelId`, `txHash`, `ipfsHash`, `gasUsed`. |
| `inference(request)` | Sends an inference transaction to the `INFERENCE_RUN` precompile and returns the output with its `txHash`. |
| `batchInference(request)` | Runs several inputs against one model. |
| `getModelInfo(modelId)` / `listModels(owner?, limit?)` | Read model metadata over JSON-RPC (`citrate_getModel`, `citrate_listModels`). |
| `purchaseModelAccess(...)` | **Disabled on purpose.** It throws, because the chain has no access-purchase precompile yet. An earlier version sent buyer funds to a precompile that never granted access. |

**Encryption fails closed.** `encrypted: true` without a configured key refuses to upload rather than falling back to plaintext. Encrypted inference also requires `recipientPublicKey`.

**Key sharing stays off-chain.** With `encryptionConfig.thresholdShares > 0` you must pass `shareHolderPublicKeys` (one distinct public key per share). Each share is wrapped to its holder and returned as `deployment.keyShareEnvelopes`; deliver those to the holders off-chain. Holders open theirs with `keyManager.unwrapKeyShare(envelope, ownerPublicKey)` and rebuild the key with `reconstructKeyFromShares(shares, threshold)`. Shares are never written to the deploy transaction (0.2.2 and earlier did that; see CHANGELOG).

### Streaming inference and events

```ts
import { WebSocketClient } from '@citratelabs/sdk';

const ws = new WebSocketClient({ url: 'wss://rpc.citrate.ai/ws' });
await ws.connect();
await ws.startStreamingInference({
  modelId,
  inputData: { prompt: 'Explain GhostDAG' },
  onPartialResult: (p) => process.stdout.write(String(p.outputData?.text ?? '')),
  onComplete: (r) => console.log('\ndone', r.txHash),
  onError: console.error,
});
```

Also: `subscribeToModel(modelId)`, `unsubscribeFromModel(modelId)`, `subscribeToMarketplace()`, `sendMessage(method, params)`, `disconnect()`. The client reconnects automatically (`reconnectAttempts`, `reconnectInterval`).

### Inference gateway (OpenAI-compatible)

Hosted models behind `https://infer.citrate.ai`. Authenticate with a `cgk_` gateway key.

```ts
import { gateway } from '@citratelabs/sdk';

const gw = new gateway.GatewayClient({ apiKey: process.env.CITRATE_GATEWAY_API_KEY! });

const reply = await gw.chatCompletions({
  model: 'gemma-4-E4B-it-Q4_K_M',
  messages: [{ role: 'user', content: 'Say hi from Citrate' }],
});
```

Also: `listModels()`, `getUsage()`, `health()`. Errors are `gateway.GatewayError` with the HTTP `status`. Point `baseUrl` at a local gateway for development.

### Identity: sign in with OIDC or Ethereum

`identity.IdentityClient` talks to `auth.citrate.ai`. The issuer is pinned to the SDK's network artifact, so a spoofed discovery document can't redirect tokens elsewhere.

```ts
import { identity } from '@citratelabs/sdk';

const id = new identity.IdentityClient({
  clientId: 'your-client-id',
  redirectUri: 'https://yourapp.example/callback',
});

// 1. Send the user to the authorize URL (PKCE is generated for you)
const { url, pkce } = id.authorizeUrl({ state, nonce });

// 2. On the callback, exchange the code
const tokens = await id.exchangeCode({ code, codeVerifier: pkce.verifier, nonce });

// 3. Read the profile: user.tier and user.capabilities come from the entitlement claim
const user = await id.userInfo(tokens.accessToken);
```

- **Sign-In with Ethereum:** `const { nonce } = await id.siweChallenge()` → `identity.buildSiweMessage({ address, nonce })` → have the wallet sign it → `id.siweVerify({ message, signature })`. The result is `{ kind: 'redirect', redirectTo }` inside an OIDC login (navigate there to finish) or `{ kind: 'token', idToken, claims }` when the authority allows the headless grant.
- **Refresh:** `refresh(refreshToken, tokens.claims.sub)`. A refreshed ID token for a different `sub` is refused.
- **Verify an ID token yourself:** `identity.verifyIdToken(token, { issuer, audience, jwks, nonce })`. It checks signature, issuer, audience, `typ`, required `exp`/`iat`, expiry and nonce, and throws `IdTokenError` on any failure.
- **Smart-wallet address:** `identity.predictWalletAddress(userId)` computes the user's counterfactual wallet offline. `identity.verifyWalletAddressOnChain(userId, provider)` confirms it against the on-chain factory and throws if they differ. Convert a Citrate user id with `identity.uuidToUserId(uuid)`.

### Embedded smart wallet (ERC-4337)

Every Citrate user has one smart account (ERC-4337 v0.7, Kernel v3) at the same address on every surface. `aa` provides the pieces to act from it:

1. `uuidToUserId(citrateUserId)` → 32-byte user id
2. `predictWalletAddress(factory, walletImpl, userId)` → the account address
3. First operation only: request a deploy permit from `auth.citrate.ai/aa/enroll-validator`, then `encodeDeployFor` + `packInitCode` → `initCode`
4. `encodeExecuteSingle` / `encodeExecuteBatch` → `callData`; read the nonce from the EntryPoint
5. `buildPackedUserOp` + `packCitratePaymasterAndData` → the operation; `getUserOpHash` → its hash
6. `signUserOpWithPasskey` (WebAuthn P-256) or `signUserOpWithEoa` → signature
7. `new aa.BundlerClient()` → `sendUserOperation`, then `waitForUserOperationReceipt`

Account recovery: `guardianRecoveryDigest`, `packGuardianSignatures`, `buildRotateSignerCall`. The bundler defaults to `aa.CITRATE_BUNDLER_URL` (`https://bundler.citrate.ai/rpc`) and accepts a `bk_` API key.

### Entitlements

Five tiers: `public`, `commercial`, `commercial.kyc`, `academic`, `confidential`. Capabilities are explicit sets, never inferred from tier order.

```ts
import { entitlements } from '@citratelabs/sdk';

entitlements.normalizeTier('commercial.kyc');               // canonical tier string
entitlements.can({ tier: user.tier }, 'gatewayKeys');       // may this user mint gateway keys?
```

Capabilities: `ecosystemTx`, `gatewayKeys`, `academicData`, `confidentialDocs`. A claim may also carry `citrateRole` and `expiresAt` (access past expiry collapses to `public`). See also `capabilitiesForClaim`, `resolveCapabilities`, `DEFAULT_CAPABILITIES`.

### Agent memory

Typed clients for a [citrate-memories](https://github.com/CitrateNetwork/citrate-memories) gateway.

```ts
import { memory } from '@citratelabs/sdk';

const mem = new memory.MemoryClient({ origin: 'https://mem-gateway.example.com', idToken });
const org = mem.org('my-org');

await org.recall({ repo: 'my-agent' });
await org.search({ repo: 'my-agent', q: 'deploy runbook' });
await org.neighbors({ repo: 'my-agent', id: nodeId });
await org.assert({ /* AssertInput */ });
```

For MCP-style agent integrations use `memory.ByomMemoryClient` (`recall`, `search`, `asOf`, `verify`, `critique`, `analogy`, `assert`, `mergeDiff`, `proposeEdge`, `confirmEdge`), authenticated with a connect token.

### Crypto utilities

- `KeyManager(privateKey?)`: address and public key, `signTransaction`, ECDH `encryptData` / `decryptData`, key-share reconstruction.
- `CryptoManager`: SHA-256 hashing, HMAC, secure random bytes, hex/string helpers. PBKDF2 uses 600,000 iterations by default.
- `ShamirSecretSharing`, `splitSecretBytes`, `reconstructSecretBytes`: threshold secret sharing over GF(256).

### React

```tsx
import { useCitrateClient, useInference } from '@citratelabs/sdk/react/hooks';

const { client, isConnected, error } = useCitrateClient({ rpcUrl: 'https://rpc.citrate.ai' });
const { execute, result, isExecuting } = useInference(client);
```

React ≥ 16.8 is an optional peer dependency; the main entry point never imports it.

## Network constants

Addresses and endpoints come from a vendored network artifact (`src/generated/federation-contract.json`), so they stay correct across chain redeployments. Import them; don't copy literals.

| Constant | Value / contents |
|---|---|
| `CHAIN_IDS.TESTNET` | `40204` |
| `DEFAULT_RPC_URLS[40204]` | `['https://rpc.citrate.ai']` |
| `DEFAULT_WS_URLS[40204]` | `'wss://rpc.citrate.ai/ws'` |
| `AA_ADDRESSES` | EntryPoint, wallet factory, paymaster, validators |
| `CONTRACT_ADDRESSES` | Named application contracts (ModelRegistry, …) |
| `MEMBERSHIP_ADDRESSES` | Membership SBT and stake vault |
| `PRECOMPILES` | The canonical precompile table (prefer this over the legacy `PRECOMPILE_ADDRESSES`) |

Block explorer: <https://explorer.citrate.ai>. Maintainers refresh the artifact with `npm run sync-contract`.

## Errors

Every SDK error extends `CitrateError`: `NetworkError`, `AuthenticationError`, `ValidationError`, `ModelNotFoundError`, `ModelDeploymentError`, `InferenceError`, `InsufficientFundsError`, `EncryptionError`, `TimeoutError`, `ConfigurationError`, `IPFSError`. Module clients add their own: `gateway.GatewayError`, `memory.MemoryError`, `identity.IdentityError`, `identity.IdTokenError`, `aa.BundlerRpcError`.

## For AI agents

Read this section before generating code against this package.

- **Entry points.** Chain: `CitrateClient`. Hosted inference: `gateway.GatewayClient`. Sign-in: `identity.IdentityClient`. Smart-account transactions: `aa.*` + `aa.BundlerClient`. Memory: `memory.MemoryClient` / `memory.ByomMemoryClient`. `GatewayClient` and the other module clients are **not** top-level exports; import the namespace (`import { gateway } from '@citratelabs/sdk'`).
- **Network.** Chain id is `40204`. Take RPC URLs, contract addresses and precompile addresses from the exported constants. Never hardcode an address.
- **Calls that sign or spend** (need `privateKey`, cost gas): `deployModel`, `inference`, `batchInference`. Everything else on `CitrateClient` is a read.
- **Deliberately disabled:** `purchaseModelAccess` always throws. Don't work around it.
- **Fail-closed behavior is intentional.** Remote `http://` endpoints are refused, encryption never downgrades to plaintext, and a wallet address that doesn't match the on-chain factory throws. Surface these errors to the user; don't disable the checks.
- **Credentials.** `privateKey`, `cgk_` gateway keys, `bk_` bundler keys, ID tokens and memory connect tokens are secrets. Read them from the environment and never log them.
- **Environment variables used by examples and tests:** `CITRATE_RPC_URL`, `CITRATE_CHAIN_ID`, `CITRATE_PRIVATE_KEY`, `CITRATE_GATEWAY_API_KEY`.

## Local development

Run against a local Citrate stack instead of the public testnet:

1. Start a devnet node from [citrate-chain](https://github.com/CitrateNetwork/citrate-chain). It serves JSON-RPC on `http://localhost:8545`.
2. Point the client at it (loopback `http://` needs no opt-in):
   ```ts
   const client = new CitrateClient({
     rpcUrl: 'http://localhost:8545',
     privateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', // public Anvil test key #0
   });
   ```
3. Optionally run [citrate-inference-gateway](https://github.com/CitrateNetwork/citrate-inference-gateway) and pass `baseUrl: 'http://localhost:8080'` to `gateway.GatewayClient`.

### Build and test this package

```bash
git clone https://github.com/CitrateNetwork/citrate-sdk-js.git
cd citrate-sdk-js
npm install
npm run build              # tsup → dist/
npm test                   # unit tests, offline
CITRATE_RPC_URL=http://localhost:8545 CITRATE_CHAIN_ID=40204 npm run test:integration
```

## Links

- Documentation: <https://docs.citrate.ai>
- Python SDK: [citrate-sdk-python](https://github.com/CitrateNetwork/citrate-sdk-python) · Marketplace SDK: [citrate-sdk-marketplace](https://github.com/CitrateNetwork/citrate-sdk-marketplace)
- Security: [Citrate security policy](https://github.com/CitrateNetwork/.github/blob/main/SECURITY.md), or report privately through GitHub
- Contributing: [contribution guide](https://github.com/CitrateNetwork/.github/blob/main/CONTRIBUTING.md)

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
