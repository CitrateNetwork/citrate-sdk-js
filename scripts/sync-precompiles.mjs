#!/usr/bin/env node
/**
 * Generate src/generated/precompiles.40204.ts (and the README precompile table) from citrate-chain.
 *
 * Sources (see scripts/lib/precompiles.cjs):
 *   <chain>/core/execution/src/precompiles/mod.rs   PURE_PRECOMPILE_ADDRESSES, AGENT_FORK_PRECOMPILE_ADDRESSES
 *   <chain>/core/execution/src/agent_fork.rs        AGENT_PRECOMPILES_PINS
 *   <chain>/contracts/addresses/40204.json          `precompiles` block
 *
 *   npm run sync-precompiles -- [--chain <dir>]       # rewrite the generated file + README table
 *   npm run verify:precompiles -- [--chain <dir>]     # non-zero if either is out of date
 *
 * --chain defaults to ../citrate-chain (sibling checkout under citrate-labs/).
 * Companion to scripts/sync-contract.mjs, which syncs the contract-address side.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const lib = require('./lib/precompiles.cjs');

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const GENERATED = join(REPO_ROOT, 'src', 'generated', 'precompiles.40204.ts');
const README = join(REPO_ROOT, 'README.md');

const args = process.argv.slice(2);
const CHECK = args.includes('--check');
const chainIdx = args.indexOf('--chain');
if (chainIdx >= 0 && !args[chainIdx + 1]) {
  console.error('[sync-precompiles] --chain needs a directory');
  process.exit(1);
}
const CHAIN = resolve(REPO_ROOT, chainIdx >= 0 ? args[chainIdx + 1] : join('..', 'citrate-chain'));

function read(rel) {
  const p = join(CHAIN, rel);
  if (!existsSync(p)) {
    console.error(`[sync-precompiles] missing ${p}\n  Pass --chain <citrate-chain checkout>.`);
    process.exit(1);
  }
  return readFileSync(p, 'utf8');
}

let table;
try {
  table = lib.buildTable({
    modRs: read(lib.PATHS.modRs),
    agentForkRs: read(lib.PATHS.agentForkRs),
    book: JSON.parse(read(lib.PATHS.book)),
  });
} catch (err) {
  console.error(`[sync-precompiles] cannot build the precompile table from ${CHAIN}: ${err.message}`);
  process.exit(1);
}

const ts = lib.renderTs(table);
const readmeNow = readFileSync(README, 'utf8');
let readmeNext;
try {
  readmeNext = lib.spliceReadme(readmeNow, table);
} catch (err) {
  console.error(`[sync-precompiles] ${err.message}`);
  process.exit(1);
}

const counts = ['hosted', 'pure', 'agent'].map((g) => `${g}=${table.entries.filter((e) => e.group === g).length}`).join(' ');
if (table.source.agentForkChainPin === null) {
  console.warn(
    `[sync-precompiles] note: agent_fork.rs pins 40204 at None; using the release activation height ` +
      `${table.source.agentForkActivationHeight} (active from genesis).`,
  );
}

if (CHECK) {
  const drift = [];
  if (!existsSync(GENERATED) || readFileSync(GENERATED, 'utf8') !== ts) drift.push('src/generated/precompiles.40204.ts');
  if (readmeNow !== readmeNext) drift.push('README.md precompile table');
  if (drift.length) {
    console.error(
      `[sync-precompiles] OUT OF SYNC with ${CHAIN}: ${drift.join(', ')}.\n` +
        '  Run `npm run sync-precompiles -- --chain <citrate-chain>` and commit.',
    );
    process.exit(1);
  }
  console.log(`[sync-precompiles] generated precompiles match the chain (${counts})`);
  process.exit(0);
}

writeFileSync(GENERATED, ts);
writeFileSync(README, readmeNext);
console.log(`[sync-precompiles] wrote ${GENERATED} and the README table (${counts})`);
