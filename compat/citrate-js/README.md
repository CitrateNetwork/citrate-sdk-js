# citrate-js (deprecated)

`citrate-js` has been renamed to **[`@citratelabs/sdk`](https://www.npmjs.com/package/@citratelabs/sdk)**.

This package is a thin compatibility shim that re-exports `@citratelabs/sdk`. It exists so existing
installs keep working through one migration cycle. Please migrate:

```bash
npm remove citrate-js
npm install @citratelabs/sdk
```

```diff
- import { CitrateClient } from 'citrate-js';
+ import { CitrateClient } from '@citratelabs/sdk';
```

See the [SDK docs](https://docs.citrate.ai/sdks/js). This shim publishes only after `@citratelabs/sdk`,
and is marked deprecated on npm at publish time (`npm deprecate`).
