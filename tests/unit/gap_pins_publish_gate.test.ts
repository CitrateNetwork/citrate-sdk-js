/**
 * Publish-gate and release-workflow pins.
 *
 * The existing gate tests use fixtures without a `repository` field, so every
 * "RED" fixture also fails the provenance check, and the specific check under
 * test could be removed without any test noticing. Here each fixture is clean
 * in every other respect (canonical name, access, registry and repository), so
 * exactly one check can reject it, and the test asserts that check's diagnostic.
 *
 * The release-workflow pins assert the structure that keeps the gate
 * authoritative even when `npm publish --ignore-scripts` skips lifecycle hooks:
 * the publish job depends on the gate job, both run the gate script directly,
 * and every action is pinned to a commit SHA.
 *
 * Fixtures are written to a fresh mkdtemp directory and removed afterwards. No
 * network access.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const repoRoot = join(__dirname, '..', '..');
const gateScript = join(repoRoot, 'scripts', 'check-publish-names.mjs');

function runGate(root: string): { code: number; stderr: string } {
  try {
    execFileSync(process.execPath, [gateScript], {
      env: { ...process.env, CITRATE_GATE_ROOT: root },
      stdio: 'pipe',
    });
    return { code: 0, stderr: '' };
  } catch (err) {
    const e = err as { status?: number; stderr?: Buffer };
    return {
      code: typeof e.status === 'number' ? e.status : 1,
      stderr: e.stderr ? e.stderr.toString('utf8') : '',
    };
  }
}

const cleanups: string[] = [];
afterAll(() => {
  for (const dir of cleanups) rmSync(dir, { recursive: true, force: true });
});

function fixture(pkg: unknown, reservation: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), 'sdkjs-gate-'));
  cleanups.push(dir);
  writeFileSync(join(dir, 'package.json'), JSON.stringify(pkg, null, 2));
  writeFileSync(join(dir, 'PUBLISH_NAMES.json'), JSON.stringify(reservation, null, 2));
  return dir;
}

const RESERVATION = {
  registry: 'npmjs.org',
  reserved: ['@fixture/sdk'],
  sourceRepo: 'CitrateNetwork/fixture-repo',
};
const CLEAN = {
  name: '@fixture/sdk',
  publishConfig: { access: 'public', registry: 'https://registry.npmjs.org/' },
  repository: { type: 'git', url: 'git+https://github.com/CitrateNetwork/fixture-repo.git' },
};

describe('publish gate: one check per fixture', () => {
  test('control: the clean fixture passes', () => {
    expect(runGate(fixture(CLEAN, RESERVATION))).toEqual({ code: 0, stderr: '' });
  });

  test('a name outside the reserved set is refused with a name-drift error', () => {
    const r = runGate(fixture({ ...CLEAN, name: '@fixture/sdk-renamed' }, RESERVATION));
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/name-drift/);
  });

  test('a missing publishConfig.access is refused', () => {
    const r = runGate(
      fixture(
        { ...CLEAN, publishConfig: { registry: 'https://registry.npmjs.org/' } },
        RESERVATION,
      ),
    );
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/publishConfig\.access is missing/);
  });

  test('an empty reserved set is refused', () => {
    const r = runGate(fixture(CLEAN, { ...RESERVATION, reserved: [] }));
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/`reserved` must be a non-empty array/);
  });

  test('a missing publishConfig.registry is refused', () => {
    const r = runGate(fixture({ ...CLEAN, publishConfig: { access: 'public' } }, RESERVATION));
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/publishConfig\.registry is missing/);
  });

  test('a blank publishConfig.registry is refused', () => {
    const r = runGate(
      fixture({ ...CLEAN, publishConfig: { access: 'public', registry: '   ' } }, RESERVATION),
    );
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/publishConfig\.registry is missing/);
  });

  test('a reservation that records no canonical registry is refused', () => {
    const { registry: _drop, ...noRegistry } = RESERVATION;
    const r = runGate(fixture(CLEAN, noRegistry));
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/PUBLISH_NAMES\.json#registry is missing/);
  });

  test('a registry on a look-alike host is refused', () => {
    const r = runGate(
      fixture(
        { ...CLEAN, publishConfig: { access: 'public', registry: 'https://registry.npmjs.org.evil.example/' } },
        RESERVATION,
      ),
    );
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/registry-drift/);
  });
});

/** Slice a workflow into its top-level jobs (two-space-indented keys under `jobs:`). */
function jobs(yml: string): Record<string, string> {
  const body = yml.slice(yml.indexOf('\njobs:') + 1);
  const out: Record<string, string> = {};
  const re = /^ {2}([A-Za-z0-9_-]+):\s*$/gm;
  const heads: Array<{ name: string; at: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) heads.push({ name: m[1]!, at: m.index });
  heads.forEach((h, i) => {
    out[h.name] = body.slice(h.at, i + 1 < heads.length ? heads[i + 1]!.at : undefined);
  });
  return out;
}

const workflowsDir = join(repoRoot, '.github', 'workflows');
const release = readFileSync(join(workflowsDir, 'release.yml'), 'utf8');
const GATE_RUN = /^\s*run:\s*node scripts\/check-publish-names\.mjs\s*$/m;

describe('release workflow keeps the gate authoritative', () => {
  const j = jobs(release);

  test('the gate job runs the gate script directly (not via an npm lifecycle hook)', () => {
    expect(j['publish-names-gate']).toBeDefined();
    expect(j['publish-names-gate']).toMatch(GATE_RUN);
  });

  test('every job that runs npm publish depends on the gate job', () => {
    const publishers = Object.entries(j).filter(([, text]) => /npm publish\b/.test(text));
    expect(publishers.length).toBeGreaterThan(0);
    for (const [name, text] of publishers) {
      expect({ name, needsGate: /^\s*needs:\s*\[?[^\n]*\bpublish-names-gate\b/m.test(text) }).toEqual({
        name,
        needsGate: true,
      });
    }
  });

  test('the publish job re-runs the gate before its first npm publish', () => {
    const text = j['publish'] ?? '';
    const gateAt = text.search(GATE_RUN);
    const publishAt = text.search(/npm publish\b/);
    expect(gateAt).toBeGreaterThanOrEqual(0);
    expect(publishAt).toBeGreaterThan(gateAt);
  });

  test('prepublishOnly still runs the gate for local publishes', () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
    expect(pkg.scripts.prepublishOnly).toMatch(/\bverify:publish-names\b/);
    expect(pkg.scripts['verify:publish-names']).toBe('node scripts/check-publish-names.mjs');
  });
});

describe('workflow actions are pinned to commit SHAs', () => {
  const files = readdirSync(workflowsDir).filter((f) => /\.ya?ml$/.test(f));

  test('there are workflows to check', () => {
    expect(files).toEqual(expect.arrayContaining(['ci.yml', 'release.yml']));
  });

  test.each(files)('%s: every `uses:` names a 40-hex commit', (file) => {
    const text = readFileSync(join(workflowsDir, file), 'utf8');
    const refs = [...text.matchAll(/^\s*(?:-\s*)?uses:\s*(\S+)/gm)].map((m) => m[1]!);
    const unpinned = refs.filter((r) => !r.startsWith('./') && !/@[0-9a-f]{40}$/.test(r));
    expect(unpinned).toEqual([]);
  });
});
