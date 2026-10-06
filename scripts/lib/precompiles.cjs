'use strict';
/**
 * Precompile table builder (shared by scripts/sync-precompiles.mjs and the unit tests).
 *
 * Inputs, all from citrate-chain:
 *   core/execution/src/precompiles/mod.rs   PURE_PRECOMPILE_ADDRESSES + AGENT_FORK_PRECOMPILE_ADDRESSES
 *                                           (each element line ends with `// 0xNNNN`)
 *   core/execution/src/agent_fork.rs        AGENT_PRECOMPILES_PINS (the 40204 activation pin)
 *   contracts/addresses/40204.json          `precompiles` block (book name -> padded address; carries
 *                                           the hosted inference family 0x0100-0x0106, not bridged)
 *
 * Every parse failure throws. A generator that silently drops an entry is worse than no generator.
 */

const CHAIN_ID = 40204;

const PATHS = {
  modRs: 'core/execution/src/precompiles/mod.rs',
  agentForkRs: 'core/execution/src/agent_fork.rs',
  book: 'contracts/addresses/40204.json',
};

/**
 * Release policy for the agent precompile fork on 40204: active from genesis on the
 * 2026-10-05 reroll (owner decision, `Some(0)`). Height 0 means the fork applies to every block
 * after genesis. If the chain source pins a different height, the build fails so the two cannot
 * disagree silently; while the chain source still says `None` (pre-release branch) this policy
 * value is used and the generated source block records `agentForkChainPin: null`.
 */
const AGENT_FORK_ACTIVATION_HEIGHT = 0;

function padAddress(hex) {
  const h = hex.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{1,40}$/.test(h)) throw new Error(`not a hex address: ${hex}`);
  return '0x' + h.padStart(40, '0');
}

/** PascalCase -> SCREAMING_SNAKE (TensorMatmulQ16 -> TENSOR_MATMUL_Q16, X402Eip712Verify -> X402_EIP712_VERIFY). */
function toKey(name) {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z])([A-Z][a-z])/g, '$1_$2')
    .toUpperCase();
}

/** SCREAMING_SNAKE -> PascalCase (LORA_APPLY -> LoraApply). */
function toName(key) {
  return key
    .toLowerCase()
    .split('_')
    .filter(Boolean)
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join('');
}

/**
 * Parse `pub const <arrayName>: [[u8; 20]; N] = [ ... ];` from mod.rs text.
 * Each element line must look like `module::path::CONST_NAME, // 0xNNNN optional note`.
 */
function parsePrecompileArray(src, arrayName) {
  const re = new RegExp(
    `pub const ${arrayName}\\s*:\\s*\\[\\[u8;\\s*20\\];\\s*(\\d+)\\]\\s*=\\s*\\[([\\s\\S]*?)\\n\\s*\\];`,
  );
  const m = src.match(re);
  if (!m) throw new Error(`cannot find \`pub const ${arrayName}: [[u8; 20]; N] = [...]\` in mod.rs`);
  const declared = Number(m[1]);
  const entries = [];
  for (const raw of m[2].split('\n')) {
    const line = raw.trim();
    if (line === '' || line.startsWith('//')) continue;
    const em = line.match(
      /^([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)\s*,\s*\/\/\s*0x([0-9A-Fa-f]{1,40})\b\s*(.*)$/,
    );
    if (!em) throw new Error(`${arrayName}: unparseable element line: ${line}`);
    const path = em[1];
    const segments = path.split('::');
    const constName = segments[segments.length - 1];
    if (!/^[A-Z][A-Z0-9_]*$/.test(constName)) throw new Error(`${arrayName}: element ${path} is not a SCREAMING_SNAKE const`);
    const qualified = segments.includes('x402') && !constName.startsWith('X402_');
    const noteText = em[3].trim().replace(/^\((.*)\)$/, '$1').trim();
    entries.push({
      path,
      constName,
      key: qualified ? `X402_${constName}` : constName,
      address: padAddress(em[2]),
      note: noteText === '' ? null : noteText,
    });
  }
  if (entries.length !== declared) {
    throw new Error(`${arrayName} declares ${declared} elements but ${entries.length} were parsed`);
  }
  const seen = new Set();
  for (const e of entries) {
    if (seen.has(e.address)) throw new Error(`${arrayName}: duplicate address ${e.address}`);
    seen.add(e.address);
  }
  return entries;
}

/** Parse the activation pin for `chainId` from agent_fork.rs. Returns the height, or null for `None`. */
function parseAgentForkPin(src, chainId) {
  const decl = src.match(/AGENT_PRECOMPILES_PINS\s*:[^=]*=\s*&\[([\s\S]*?)\];/);
  if (!decl) throw new Error('cannot find AGENT_PRECOMPILES_PINS in agent_fork.rs');
  const m = decl[1].match(new RegExp(`\\(\\s*${chainId}\\s*,\\s*(None|Some\\(\\s*(\\d+)\\s*\\))\\s*\\)`));
  if (!m) throw new Error(`AGENT_PRECOMPILES_PINS has no entry for chain ${chainId}`);
  return m[1] === 'None' ? null : Number(m[2]);
}

/**
 * Merge the two arrays and the book block into one table, sorted by address.
 * group: 'hosted' (book only, not bridged into REVM), 'pure' (PURE_PRECOMPILE_ADDRESSES),
 * 'agent' (AGENT_FORK_PRECOMPILE_ADDRESSES).
 */
function buildTable({ modRs, agentForkRs, book }) {
  if (book.chainId !== CHAIN_ID) throw new Error(`book chainId ${book.chainId}, expected ${CHAIN_ID}`);
  if (!book.precompiles || typeof book.precompiles !== 'object') throw new Error('book has no `precompiles` block');

  const pure = parsePrecompileArray(modRs, 'PURE_PRECOMPILE_ADDRESSES');
  const agent = parsePrecompileArray(modRs, 'AGENT_FORK_PRECOMPILE_ADDRESSES');
  const chainPin = parseAgentForkPin(agentForkRs, CHAIN_ID);
  if (chainPin !== null && chainPin !== AGENT_FORK_ACTIVATION_HEIGHT) {
    throw new Error(
      `agent_fork.rs pins 40204 at Some(${chainPin}), but this SDK release ships the agent precompiles ` +
        `active from genesis (Some(${AGENT_FORK_ACTIVATION_HEIGHT})). Reconcile before regenerating.`,
    );
  }

  const bookByAddress = new Map();
  for (const [name, addr] of Object.entries(book.precompiles)) {
    const a = padAddress(addr);
    if (bookByAddress.has(a)) throw new Error(`book precompiles: duplicate address ${a}`);
    bookByAddress.set(a, name);
  }

  const entries = [];
  const used = new Set();
  const push = (group, e) => {
    if (used.has(e.address)) throw new Error(`address ${e.address} appears in more than one array`);
    used.add(e.address);
    const bookName = bookByAddress.get(e.address);
    entries.push({
      name: bookName ?? toName(e.key),
      key: e.key,
      address: e.address,
      group,
      bridged: true,
      activeFromGenesis: true,
      chainConst: e.path,
      inBook: bookName !== undefined,
      note: e.note,
    });
  };
  for (const e of pure) push('pure', e);
  for (const e of agent) push('agent', e);
  for (const [address, name] of bookByAddress) {
    if (used.has(address)) continue;
    used.add(address);
    entries.push({
      name,
      key: toKey(name),
      address,
      group: 'hosted',
      bridged: false,
      activeFromGenesis: true,
      chainConst: null,
      inBook: true,
      note: null,
    });
  }

  const keys = new Set();
  for (const e of entries) {
    if (keys.has(e.key)) throw new Error(`duplicate generated key ${e.key}`);
    keys.add(e.key);
  }
  entries.sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));

  return {
    source: {
      chainId: CHAIN_ID,
      files: [PATHS.modRs, PATHS.agentForkRs, PATHS.book],
      agentForkChainPin: chainPin,
      agentForkActivationHeight: AGENT_FORK_ACTIVATION_HEIGHT,
    },
    entries,
  };
}

const q = (s) => (s === null ? 'null' : `'${String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`);

function renderTs(table) {
  const { source, entries } = table;
  const lines = [];
  lines.push('/**');
  lines.push(' * AUTO-GENERATED by scripts/sync-precompiles.mjs from citrate-chain. Do not edit by hand.');
  lines.push(' *');
  lines.push(' *   npm run sync-precompiles -- --chain ../citrate-chain    # regenerate');
  lines.push(' *   npm run verify:precompiles -- --chain ../citrate-chain  # CI gate: non-zero on drift');
  lines.push(' *');
  lines.push(' * Sources (relative to the citrate-chain checkout):');
  for (const f of source.files) lines.push(` *   ${f}`);
  lines.push(' */');
  lines.push('');
  lines.push("export type PrecompileGroup = 'hosted' | 'pure' | 'agent';");
  lines.push('');
  lines.push('export interface ChainPrecompile {');
  lines.push('  /** Book name (40204.json `precompiles`), or PascalCase of the chain const when the book lacks it. */');
  lines.push('  readonly name: string;');
  lines.push('  /** Key in PRECOMPILE_ADDRESSES / CHAIN_PRECOMPILE_ADDRESSES. */');
  lines.push('  readonly key: string;');
  lines.push('  readonly address: `0x${string}`;');
  lines.push("  /** 'pure' and 'agent' are bridged into REVM (mod.rs arrays); 'hosted' is the book-only inference family. */");
  lines.push('  readonly group: PrecompileGroup;');
  lines.push('  readonly bridged: boolean;');
  lines.push('  /** In force from the first block after the 40204 genesis. */');
  lines.push('  readonly activeFromGenesis: boolean;');
  lines.push('  /** Rust path of the address const in mod.rs, or null for book-only entries. */');
  lines.push('  readonly chainConst: string | null;');
  lines.push("  /** Whether the chain book's `precompiles` block lists this address. */");
  lines.push('  readonly inBook: boolean;');
  lines.push('  readonly note: string | null;');
  lines.push('}');
  lines.push('');
  lines.push('export const CHAIN_PRECOMPILE_SOURCE = {');
  lines.push(`  chainId: ${source.chainId},`);
  lines.push(`  files: [${source.files.map(q).join(', ')}],`);
  lines.push(`  agentForkChainPin: ${source.agentForkChainPin === null ? 'null' : source.agentForkChainPin},`);
  lines.push(`  agentForkActivationHeight: ${source.agentForkActivationHeight},`);
  lines.push('} as const;');
  lines.push('');
  lines.push('export const CHAIN_PRECOMPILES: readonly ChainPrecompile[] = [');
  for (const e of entries) {
    lines.push(
      `  { name: ${q(e.name)}, key: ${q(e.key)}, address: ${q(e.address)}, group: ${q(e.group)}, ` +
        `bridged: ${e.bridged}, activeFromGenesis: ${e.activeFromGenesis}, chainConst: ${q(e.chainConst)}, ` +
        `inBook: ${e.inBook}, note: ${q(e.note)} },`,
    );
  }
  lines.push('];');
  lines.push('');
  lines.push('export const CHAIN_PRECOMPILE_ADDRESSES = {');
  for (const e of entries) lines.push(`  ${e.key}: ${q(e.address)},`);
  lines.push('} as const;');
  lines.push('');
  return lines.join('\n');
}

const README_BEGIN = '<!-- precompiles:begin (generated by `npm run sync-precompiles`; do not edit) -->';
const README_END = '<!-- precompiles:end -->';

function renderReadmeTable(table) {
  const rows = ['| Key | Address | Group | Name | In book |', '|---|---|---|---|---|'];
  for (const e of table.entries) {
    rows.push(`| \`${e.key}\` | \`${e.address}\` | ${e.group} | ${e.name} | ${e.inBook ? 'yes' : 'no'} |`);
  }
  return rows.join('\n');
}

/** Replace the marker block in README text. Throws if the markers are missing. */
function spliceReadme(readme, table) {
  const start = readme.indexOf(README_BEGIN);
  const end = readme.indexOf(README_END);
  if (start < 0 || end < 0 || end < start) {
    throw new Error('README.md is missing the precompiles:begin / precompiles:end markers');
  }
  return readme.slice(0, start + README_BEGIN.length) + '\n' + renderReadmeTable(table) + '\n' + readme.slice(end);
}

module.exports = {
  CHAIN_ID,
  PATHS,
  AGENT_FORK_ACTIVATION_HEIGHT,
  padAddress,
  toKey,
  toName,
  parsePrecompileArray,
  parseAgentForkPin,
  buildTable,
  renderTs,
  renderReadmeTable,
  spliceReadme,
};
