# citrate-sdk-js

*Part of the **[Citrate Network](https://citrate.ai)** — own the means of computation. · [Docs](https://docs.citrate.ai) · [Run a node](https://citrate.ai/download) · [Contribute → free membership](https://github.com/CitrateNetwork/.github/blob/main/CONTRIBUTING.md)*
> The canonical TypeScript/JavaScript SDK for the Citrate Network (chain **40204**) — talk to the chain, deploy and run models, and call the inference gateway from Node or the browser.

## What it is
`@citratelabs/sdk` is the reference client for the Citrate distributed-AI network: a
JSON-RPC client (`CitrateClient`) for chain reads/writes and model/inference precompiles,
an OpenAI-compatible inference-gateway client (`GatewayClient`), plus embedded
smart-account (ERC-4337) wallet, OIDC/SIWE identity, and entitlement helpers. Chain-varying
values (RPC/WS endpoints, contract addresses, chain id 40204) are derived from a vendored
federation-contract artifact, so they can never drift against a chain re-roll. This is the
**canonical** SDK; the Python client mirrors it.

See the concepts in the docs: <https://docs.citrate.ai>.
Depends on a running chain node ([citrate-chain](https://github.com/CitrateNetwork/citrate-chain))
and, for inference, the gateway ([citrate-inference-gateway](https://github.com/CitrateNetwork/citrate-inference-gateway)).

## Prerequisites
```bash
# Node 16+ (engines floor); Node 20 LTS recommended
node --version   # >= v16.0.0
npm --version

# Toolchain versions are pinned in package.json; no global installs needed.
# Optional, only for the "Connect it locally" section:
#   - a local Citrate devnet node exposing JSON-RPC on :8545
#   - foundry (anvil/forge) if you run the chain's local devnet + contract book
```

## Build from source
```bash
git clone https://github.com/CitrateNetwork/citrate-sdk-js.git
cd citrate-sdk-js
npm install
npm run build          # tsup → dist/ (index.js, index.mjs, index.d.ts, react/hooks.*)
npm test               # unit tests (jest); integration tests are excluded here
```
Expected artifacts land in `dist/`. Unit tests run offline; integration tests require a
node (see below). Build is fast (< 30s) and low-RAM.

## Run locally
This is a library, not a service — there is no port to open. Install it into an app and
point it at a network:

```bash
# In your app
npm install @citratelabs/sdk
```

30-second Quickstart (against the public testnet, chain 40204):
```ts
import { CitrateClient } from '@citratelabs/sdk';

const client = new CitrateClient({
  rpcUrl: 'https://rpc.citrate.ai',            // testnet default (chain 40204)
  privateKey: process.env.CITRATE_PRIVATE_KEY, // optional; required to sign
});

const chainId = await client.getChainId();     // 40204
console.log('connected to chain', chainId);
const balance = await client.getBalance();     // wallet balance in wei (bigint)
console.log('balance', balance.toString());
```

Call the inference gateway (OpenAI-compatible; needs a `cgk_` key):
```ts
import { GatewayClient } from '@citratelabs/sdk';

const gw = new GatewayClient({ apiKey: process.env.CITRATE_GATEWAY_API_KEY! });
const res = await gw.chatCompletions({
  model: 'gemma-4-E4B-it-Q4_K_M',
  messages: [{ role: 'user', content: 'Say hi from Citrate' }],
});
console.log(res);
```
Verify it's up: `getChainId()` returning `40204` confirms the RPC is reachable.

> Security: the client **fails closed** on a remote plaintext (`http://` / `ws://`) RPC or
> gateway URL — signed transactions and keys would otherwise go out in cleartext. Loopback
> (`localhost`/`127.0.0.1`) is always allowed. For a trusted TLS-less internal host, pass
> `allowInsecureHttp: true`.

## Connect it locally  ← the differentiator
Point the SDK at a local Citrate stack on one machine instead of the public testnet.

1. **Local chain** — run a Citrate devnet node (chain 40204) from
   [citrate-chain](https://github.com/CitrateNetwork/citrate-chain) and deploy the contract
   book with its foundry script. It exposes JSON-RPC on `http://localhost:8545`.
2. **Point the SDK at it** (loopback `http://` is allowed without opt-in):
   ```ts
   const client = new CitrateClient({
     rpcUrl: 'http://localhost:8545',
     privateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', // anvil acct #0
   });
   console.log(await client.getChainId()); // expect 40204
   ```
3. **Local inference gateway** (optional) — run
   [citrate-inference-gateway](https://github.com/CitrateNetwork/citrate-inference-gateway)
   and point the gateway client at it:
   ```ts
   const gw = new GatewayClient({
     apiKey: process.env.CITRATE_GATEWAY_API_KEY!,
     baseUrl: 'http://localhost:8080',   // loopback allowed
   });
   ```
4. **End-to-end check** — run the integration suite against your local node:
   ```bash
   CITRATE_RPC_URL=http://localhost:8545 CITRATE_CHAIN_ID=40204 npm run test:integration
   # or the convenience script:
   npm run test:integration:testnet
   ```

For the full multi-repo bring-up (chain → identity → bundler → gateway → SDKs), see the
LOCAL_STACK guide at <https://docs.citrate.ai>.

## Configuration
| Env var | Default | Purpose |
|---------|---------|---------|
| `CITRATE_RPC_URL` | `http://localhost:8545` (tests) / `https://rpc.citrate.ai` (testnet) | chain JSON-RPC endpoint |
| `CITRATE_CHAIN_ID` | `40204` | expected chain id (used by the integration suite) |
| `CITRATE_PRIVATE_KEY` | — | signer key for transactions/inference |
| `CITRATE_GATEWAY_API_KEY` | — | `cgk_` bearer key for the inference gateway |

`CitrateClient` also accepts `rpcUrl` as an **array** for multi-RPC failover, `ipfsApiUrl`
(unset = skip IPFS upload, use the content hash), `timeout`, `retries`, and
`allowInsecureHttp`. The gateway base URL and chain id default to the vendored federation
artifact and are refreshed with `npm run sync-contract`.

## Links
- Docs: <https://docs.citrate.ai>
- Depends on: [citrate-chain](https://github.com/CitrateNetwork/citrate-chain) · [citrate-inference-gateway](https://github.com/CitrateNetwork/citrate-inference-gateway) · [citrate-identity](https://github.com/CitrateNetwork/citrate-identity)
- Consumed by: [citrate-sdk-marketplace](https://github.com/CitrateNetwork/citrate-sdk-marketplace) and the Citrate webapps/agents
- Contributing (DCO): `CONTRIBUTING.md` · Security: `SECURITY.md` · License: [`LICENSE`](LICENSE)

## License

Licensed under the Apache License, Version 2.0 (see [`LICENSE`](LICENSE)). This is the open-source infrastructure tier of Citrate's open-core model. The commercial application layer is source-available under BUSL-1.1. Licensor: Citrate Inc.
