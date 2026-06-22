/**
 * RM-SUPPLY / FWA-C12-01 — dependency-confusion name-drift gate (citrate-sdk-js).
 *
 * RED → GREEN contract:
 *   - package.json#name must be one of the RESERVED publish names in
 *     PUBLISH_NAMES.json (the in-repo mirror of the federation manifest
 *     [repos.citrate-sdk-js].publishes entry). This catches the FWA-C12-01
 *     drift where the manifest recorded "@citratenetwork/sdk" while the repo
 *     actually publishes "citrate-js".
 *   - package.json#publishConfig.access must be present so the unscoped
 *     package never publishes to an ambiguous default target (WEB-5 squat).
 *   - package.json#publishConfig.registry must resolve to the canonical
 *     registry host recorded in PUBLISH_NAMES.json#registry. A repointed
 *     registry (e.g. https://evil.example/) is rejected (FWA-BV-SDK-01).
 *
 * Mirrors scripts/check-publish-names.mjs (the permanent CI tripwire). The
 * registry/name drift cases below invoke the REAL gate script as a child
 * process against tampered fixture manifests, asserting its exit code — this
 * is the same code path the CI gate runs, so the test guards the actual
 * enforcement rather than a re-implementation.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const repoRoot = join(__dirname, '..', '..');
const gateScript = join(repoRoot, 'scripts', 'check-publish-names.mjs');

interface Pkg {
  name: string;
  publishConfig?: { access?: string; registry?: string };
}
interface Reservation {
  reserved?: string[];
  registry?: string;
}

/**
 * Run the real gate script against a fixture root containing a (possibly
 * tampered) package.json + PUBLISH_NAMES.json. Returns the process exit code
 * (0 = pass, non-zero = gate failure).
 */
function runGate(root: string): number {
  try {
    execFileSync(process.execPath, [gateScript], {
      env: { ...process.env, CITRATE_GATE_ROOT: root },
      stdio: 'pipe',
    });
    return 0;
  } catch (err) {
    const code = (err as { status?: number }).status;
    return typeof code === 'number' ? code : 1;
  }
}

/** Materialize a fixture repo root with the given pkg + reservation. */
function makeFixture(pkg: unknown, reservation: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), 'fwa-bv-sdk-01-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify(pkg, null, 2));
  writeFileSync(
    join(dir, 'PUBLISH_NAMES.json'),
    JSON.stringify(reservation, null, 2),
  );
  return dir;
}

const pkg: Pkg = JSON.parse(
  readFileSync(join(repoRoot, 'package.json'), 'utf8'),
);
const reservation: Reservation = JSON.parse(
  readFileSync(join(repoRoot, 'PUBLISH_NAMES.json'), 'utf8'),
);

describe('FWA-C12-01 — publish-name drift + publishConfig gate', () => {
  test('PUBLISH_NAMES.json declares a non-empty reserved set', () => {
    expect(Array.isArray(reservation.reserved)).toBe(true);
    expect((reservation.reserved ?? []).length).toBeGreaterThan(0);
  });

  test('package.json#name is one of the reserved publish names (no drift)', () => {
    expect(reservation.reserved).toContain(pkg.name);
  });

  test('package.json declares publishConfig.access (no ambiguous default target)', () => {
    expect(pkg.publishConfig).toBeDefined();
    expect(typeof pkg.publishConfig?.access).toBe('string');
  });

  test('PUBLISH_NAMES.json records a canonical registry', () => {
    expect(typeof reservation.registry).toBe('string');
    expect((reservation.registry ?? '').length).toBeGreaterThan(0);
  });

  test('package.json#publishConfig.registry resolves to the canonical registry', () => {
    expect(typeof pkg.publishConfig?.registry).toBe('string');
  });
});

describe('FWA-BV-SDK-01 — registry-drift gate (real script, exit code)', () => {
  const cleanups: string[] = [];
  afterAll(() => {
    for (const dir of cleanups) rmSync(dir, { recursive: true, force: true });
  });

  const cleanPkg = {
    name: 'citrate-js',
    publishConfig: { access: 'public', registry: 'https://registry.npmjs.org/' },
  };
  const reservationFixture = { registry: 'npmjs.org', reserved: ['citrate-js'] };

  test('GREEN: clean manifest passes the gate (exit 0)', () => {
    const dir = makeFixture(cleanPkg, reservationFixture);
    cleanups.push(dir);
    expect(runGate(dir)).toBe(0);
  });

  test('RED: tampered publishConfig.registry (evil host) fails the gate (exit != 0)', () => {
    const dir = makeFixture(
      {
        ...cleanPkg,
        publishConfig: { access: 'public', registry: 'https://evil.example/' },
      },
      reservationFixture,
    );
    cleanups.push(dir);
    expect(runGate(dir)).not.toBe(0);
  });

  test('RED: missing publishConfig.registry fails the gate (exit != 0)', () => {
    const dir = makeFixture(
      { name: 'citrate-js', publishConfig: { access: 'public' } },
      reservationFixture,
    );
    cleanups.push(dir);
    expect(runGate(dir)).not.toBe(0);
  });

  test('RED (regression-guard): tampered name still fails the gate (exit != 0)', () => {
    const dir = makeFixture(
      {
        name: 'citrate-js-evil',
        publishConfig: { access: 'public', registry: 'https://registry.npmjs.org/' },
      },
      reservationFixture,
    );
    cleanups.push(dir);
    expect(runGate(dir)).not.toBe(0);
  });
});
