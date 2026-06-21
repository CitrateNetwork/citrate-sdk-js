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
 *
 * Mirrors scripts/check-publish-names.mjs (the permanent CI tripwire). Kept
 * dependency-free / self-contained so it runs under ts-jest without ESM friction.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const repoRoot = join(__dirname, '..', '..');

interface Pkg {
  name: string;
  publishConfig?: { access?: string };
}
interface Reservation {
  reserved?: string[];
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
});
