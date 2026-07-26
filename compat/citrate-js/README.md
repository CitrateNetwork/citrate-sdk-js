# citrate-js (deprecated)

`citrate-js` has been renamed to **[`@citratenetwork/sdk`](https://www.npmjs.com/package/@citratenetwork/sdk)**.

This package is a thin compatibility shim that re-exports `@citratenetwork/sdk`. It exists so existing
installs keep working through one migration cycle. Please migrate:

```bash
npm remove citrate-js
npm install @citratenetwork/sdk
```

```diff
- import { CitrateClient } from 'citrate-js';
+ import { CitrateClient } from '@citratenetwork/sdk';
```

See the [SDK docs](https://docs.citrate.ai/sdks/js). This shim publishes only after `@citratenetwork/sdk`,
and is marked deprecated on npm at publish time (`npm deprecate`).
