import { defineConfig } from 'tsup';

// Dual ESM + CJS build (DEVX-S3, ADR-0003). esbuild resolves the vendored
// federation-contract.json import inline, so there is no raw-Node-ESM JSON or
// extension footgun. Runtime deps stay external; React is an optional peer.
export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'react/hooks': 'src/react/hooks.ts',
  },
  format: ['cjs', 'esm'], // → dist/*.js (cjs) + dist/*.mjs (esm)
  dts: true,
  sourcemap: false,
  clean: true,
  splitting: false,
  treeshake: true,
  external: ['react', 'react-dom', 'ethers', 'axios', 'eventemitter3'],
});
