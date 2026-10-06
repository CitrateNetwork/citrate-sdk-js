/**
 * Precompile address sync (HUP reroll book sync).
 *
 * PRECOMPILE_ADDRESSES used to be hand-written. It is now built from
 * src/generated/precompiles.40204.ts, which scripts/sync-precompiles.mjs generates from
 * citrate-chain (core/execution/src/precompiles/mod.rs arrays + the 40204.json book's
 * `precompiles` block). These tests pin three things:
 *   1. the exported constants are exactly the generated data (plus the documented legacy keys),
 *   2. the agent precompiles (0x0112, 0x0113, 0x0121, 0x0122) are present and active from genesis,
 *   3. the mod.rs parser reads the real array shape and fails loudly on anything else.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PRECOMPILE_ADDRESSES, CHAIN_PRECOMPILES, CHAIN_PRECOMPILE_SOURCE } from '../../src/utils/constants';
import { CHAIN_PRECOMPILE_ADDRESSES } from '../../src/generated/precompiles.40204';

interface ParsedEntry {
  path: string;
  constName: string;
  key: string;
  address: string;
  note: string | null;
}
interface Parser {
  parsePrecompileArray(src: string, arrayName: string): ParsedEntry[];
  parseAgentForkPin(src: string, chainId: number): number | null;
  buildTable(input: {
    modRs: string;
    agentForkRs: string;
    book: { chainId: number; precompiles: Record<string, string> };
  }): {
    entries: Array<{ name: string; key: string; address: string; group: string; bridged: boolean; activeFromGenesis: boolean }>;
  };
}
// eslint-disable-next-line @typescript-eslint/no-var-requires
const parser = require('../../scripts/lib/precompiles.cjs') as Parser;

const root = join(__dirname, '..', '..');
const pad = (short: string) => '0x' + short.padStart(40, '0');

const FIXTURE_MOD_RS = `
/// doc comment
pub const PURE_PRECOMPILE_ADDRESSES: [[u8; 20]; 3] = [
    verify::addresses::TENSOR_COMMIT,          // 0x0107
    commd_fold_verify::FOLD_COMMD_VERIFY,      // 0x0130 (feature-gated verifier)
    x402::addresses::EIP712_VERIFY,            // 0x0200
];

pub const AGENT_FORK_PRECOMPILE_ADDRESSES: [[u8; 20]; 2] = [
    lora::LORA_APPLY,                    // 0x0112
    agent_ops::AGENT_OPS,                // 0x0122
];
`;
const FIXTURE_AGENT_FORK_RS = 'pub const AGENT_PRECOMPILES_PINS: &[(u64, Option<u64>)] = &[(40204, None)];';
const FIXTURE_BOOK = {
  chainId: 40204,
  precompiles: {
    ModelDeploy: pad('100'),
    TensorCommit: pad('107'),
    X402Eip712Verify: pad('200'),
  },
};

describe('mod.rs parser (fixture)', () => {
  test('reads element path, const name, key and padded address from each line', () => {
    const pure = parser.parsePrecompileArray(FIXTURE_MOD_RS, 'PURE_PRECOMPILE_ADDRESSES');
    expect(pure.map((e) => e.address)).toEqual([pad('107'), pad('130'), pad('200')]);
    expect(pure[0]).toMatchObject({ path: 'verify::addresses::TENSOR_COMMIT', constName: 'TENSOR_COMMIT', key: 'TENSOR_COMMIT' });
    expect(pure[1]?.note).toBe('feature-gated verifier');
    // x402 consts are module-qualified in the key so EIP712_VERIFY cannot collide with a future one.
    expect(pure[2]?.key).toBe('X402_EIP712_VERIFY');
    const agent = parser.parsePrecompileArray(FIXTURE_MOD_RS, 'AGENT_FORK_PRECOMPILE_ADDRESSES');
    expect(agent.map((e) => e.key)).toEqual(['LORA_APPLY', 'AGENT_OPS']);
  });

  test('fails when the array is missing', () => {
    expect(() => parser.parsePrecompileArray('fn main() {}', 'AGENT_FORK_PRECOMPILE_ADDRESSES')).toThrow(/AGENT_FORK_PRECOMPILE_ADDRESSES/);
  });

  test('fails on an element line without the // 0xNNNN address comment', () => {
    const bad = FIXTURE_MOD_RS.replace('lora::LORA_APPLY,                    // 0x0112', 'lora::LORA_APPLY,');
    expect(() => parser.parsePrecompileArray(bad, 'AGENT_FORK_PRECOMPILE_ADDRESSES')).toThrow(/unparseable/);
  });

  test('fails when the declared length disagrees with the parsed element count', () => {
    const bad = FIXTURE_MOD_RS.replace('[[u8; 20]; 2]', '[[u8; 20]; 4]');
    expect(() => parser.parsePrecompileArray(bad, 'AGENT_FORK_PRECOMPILE_ADDRESSES')).toThrow(/declares 4/);
  });

  test('reads the 40204 agent fork pin (None or Some(h))', () => {
    expect(parser.parseAgentForkPin(FIXTURE_AGENT_FORK_RS, 40204)).toBeNull();
    expect(parser.parseAgentForkPin(FIXTURE_AGENT_FORK_RS.replace('None', 'Some(0)'), 40204)).toBe(0);
    expect(() => parser.parseAgentForkPin('nothing here', 40204)).toThrow(/AGENT_PRECOMPILES_PINS/);
  });

  test('a chain pin above genesis contradicts the genesis activation and fails', () => {
    expect(() =>
      parser.buildTable({ modRs: FIXTURE_MOD_RS, agentForkRs: FIXTURE_AGENT_FORK_RS.replace('None', 'Some(5000)'), book: FIXTURE_BOOK }),
    ).toThrow(/genesis/);
  });

  test('buildTable merges book names with the arrays and groups every address', () => {
    const { entries } = parser.buildTable({ modRs: FIXTURE_MOD_RS, agentForkRs: FIXTURE_AGENT_FORK_RS, book: FIXTURE_BOOK });
    const byAddr = Object.fromEntries(entries.map((e) => [e.address, e]));
    expect(byAddr[pad('100')]).toMatchObject({ name: 'ModelDeploy', key: 'MODEL_DEPLOY', group: 'hosted', bridged: false });
    expect(byAddr[pad('107')]).toMatchObject({ name: 'TensorCommit', key: 'TENSOR_COMMIT', group: 'pure', bridged: true });
    expect(byAddr[pad('130')]).toMatchObject({ name: 'FoldCommdVerify', key: 'FOLD_COMMD_VERIFY', group: 'pure' });
    expect(byAddr[pad('112')]).toMatchObject({ name: 'LoraApply', group: 'agent', bridged: true, activeFromGenesis: true });
    expect(entries.map((e) => e.address)).toEqual([...entries.map((e) => e.address)].sort());
  });
});

describe('PRECOMPILE_ADDRESSES is built from the generated chain table', () => {
  test('every generated entry is exported under its key with the same address', () => {
    expect(CHAIN_PRECOMPILES.length).toBeGreaterThan(0);
    const exported = PRECOMPILE_ADDRESSES as Record<string, string>;
    for (const e of CHAIN_PRECOMPILES) {
      expect(exported[e.key]).toBe(e.address);
      expect(CHAIN_PRECOMPILE_ADDRESSES[e.key as keyof typeof CHAIN_PRECOMPILE_ADDRESSES]).toBe(e.address);
    }
  });

  test('the only keys beyond the generated table are the documented legacy ones', () => {
    const generatedKeys = new Set(CHAIN_PRECOMPILES.map((e) => e.key));
    const extra = Object.keys(PRECOMPILE_ADDRESSES).filter((k) => !generatedKeys.has(k)).sort();
    expect(extra).toEqual(
      [
        'ARTIFACT',
        'GOVERNANCE',
        'INFERENCE_BATCH',
        'INFERENCE_BENCHMARK',
        'INFERENCE_DEPLOY',
        'INFERENCE_ENCRYPT',
        'INFERENCE_METADATA',
        'INFERENCE_RUN',
        'INFERENCE_VERIFY',
        'MODEL',
      ].sort(),
    );
  });

  test('legacy keys keep their addresses (backward compatible)', () => {
    expect(PRECOMPILE_ADDRESSES).toMatchObject({
      MODEL: pad('1000'),
      ARTIFACT: pad('1002'),
      GOVERNANCE: pad('1003'),
      INFERENCE_DEPLOY: pad('100'),
      INFERENCE_RUN: pad('101'),
      INFERENCE_BATCH: pad('102'),
      INFERENCE_METADATA: pad('103'),
      INFERENCE_VERIFY: pad('104'),
      INFERENCE_BENCHMARK: pad('105'),
      INFERENCE_ENCRYPT: pad('106'),
    });
  });

  test('the four agent precompiles are present and active from genesis', () => {
    const expected: Record<string, string> = {
      LORA_APPLY: pad('112'),
      LORA_MERGE: pad('113'),
      MEMORY_ANCHOR_VERIFY: pad('121'),
      AGENT_OPS: pad('122'),
    };
    for (const [key, address] of Object.entries(expected)) {
      expect((PRECOMPILE_ADDRESSES as Record<string, string>)[key]).toBe(address);
      const entry = CHAIN_PRECOMPILES.find((e) => e.key === key);
      expect(entry).toMatchObject({ address, group: 'agent', bridged: true, activeFromGenesis: true });
    }
    expect(CHAIN_PRECOMPILES.filter((e) => e.group === 'agent')).toHaveLength(4);
    expect(CHAIN_PRECOMPILE_SOURCE.chainId).toBe(40204);
    expect(CHAIN_PRECOMPILE_SOURCE.agentForkActivationHeight).toBe(0);
  });

  test('the bridged pure set from mod.rs is present, including 0x0130', () => {
    const pure = CHAIN_PRECOMPILES.filter((e) => e.group === 'pure');
    expect(pure).toHaveLength(16);
    expect((PRECOMPILE_ADDRESSES as Record<string, string>).FOLD_COMMD_VERIFY).toBe(pad('130'));
    expect((PRECOMPILE_ADDRESSES as Record<string, string>).INFERENCE_PROOF_VERIFY).toBe(pad('108'));
  });

  test('the README precompile table is the generated one', () => {
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    const block = readme.match(/<!-- precompiles:begin[^>]*-->([\s\S]*?)<!-- precompiles:end -->/);
    expect(block).not.toBeNull();
    for (const e of CHAIN_PRECOMPILES) {
      expect(block?.[1]).toContain(`| \`${e.key}\` | \`${e.address}\` |`);
    }
  });
});
