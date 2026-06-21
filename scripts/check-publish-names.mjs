#!/usr/bin/env node
/**
 * FWA-C12-01 name-drift tripwire (citrate-sdk-js).
 *
 * Asserts the supply-chain publish contract for this repo:
 *   1. package.json#name is one of the RESERVED publish names recorded in
 *      PUBLISH_NAMES.json (the in-repo mirror of the federation manifest
 *      [repos.citrate-sdk-js].publishes entry). No silent rename can drift
 *      the published name away from the defensively-reserved string.
 *   2. publishConfig is present with an explicit `access` so the package
 *      never falls back to an ambiguous default publish target
 *      (dependency-confusion hardening — WEB-5 / FWA-C12-01).
 *
 * Exit 0 on pass, exit 1 with a diagnostic on any drift. This is the
 * permanent CI gate; the jest test wraps the same checks so it runs in the
 * unit suite too.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, '..');

export function checkPublishNames(root = repoRoot) {
  const errors = [];
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const reservation = JSON.parse(
    readFileSync(join(root, 'PUBLISH_NAMES.json'), 'utf8'),
  );
  const reserved = reservation.reserved ?? [];

  if (!Array.isArray(reserved) || reserved.length === 0) {
    errors.push('PUBLISH_NAMES.json: `reserved` must be a non-empty array');
  }

  if (!reserved.includes(pkg.name)) {
    errors.push(
      `name-drift: package.json#name "${pkg.name}" is not in the reserved ` +
        `publish set ${JSON.stringify(reserved)}. Update PUBLISH_NAMES.json ` +
        `AND the federation manifest [repos.citrate-sdk-js].publishes together.`,
    );
  }

  if (!pkg.publishConfig || typeof pkg.publishConfig.access !== 'string') {
    errors.push(
      'package.json#publishConfig.access is missing — an unscoped package ' +
        'with no explicit publishConfig is dependency-confusion-prone (FWA-C12-01).',
    );
  }

  return errors;
}

// Run directly (CLI / CI), not when imported by the jest test.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const errors = checkPublishNames();
  if (errors.length > 0) {
    console.error('FWA-C12-01 publish-name gate FAILED:');
    for (const e of errors) console.error('  - ' + e);
    process.exit(1);
  }
  console.log('FWA-C12-01 publish-name gate PASSED.');
}
