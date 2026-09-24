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
 *   3. publishConfig.registry resolves to the canonical registry host
 *      recorded in PUBLISH_NAMES.json#registry. A repointed registry
 *      (e.g. https://evil.example/) is rejected, closing the registry-drift
 *      exfiltration hole (FWA-BV-SDK-01). The recorded value is compared on
 *      normalized host so "npmjs.org" matches "https://registry.npmjs.org/".
 *
 * Exit 0 on pass, exit 1 with a diagnostic on any drift. This is the
 * permanent CI gate; the jest test wraps the same checks so it runs in the
 * unit suite too.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, '..');

/**
 * Normalize a registry value to a bare lowercase host for comparison.
 * Accepts either a bare host ("npmjs.org") or a full URL
 * ("https://registry.npmjs.org/"). Strips a leading "registry." label so the
 * canonical "npmjs.org" reservation matches the conventional
 * "registry.npmjs.org" publish endpoint. Returns null if unparseable.
 */
export function normalizeRegistryHost(value) {
  if (typeof value !== 'string' || value.trim() === '') return null;
  let host;
  try {
    // If it parses as a URL, use the hostname; otherwise treat as bare host.
    host = new URL(value).hostname;
  } catch {
    host = value.replace(/^[a-z]+:\/\//i, '').split('/')[0].split(':')[0];
  }
  host = host.toLowerCase().replace(/\.$/, '');
  if (host === '') return null;
  return host.replace(/^registry\./, '');
}

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

  // FWA-BV-SDK-01: the registry must resolve to the canonical host recorded in
  // PUBLISH_NAMES.json#registry. A drifted/missing registry (e.g. a repointed
  // https://evil.example/) is a publish-exfiltration vector and is rejected.
  const expectedRegistry = reservation.registry;
  const expectedHost = normalizeRegistryHost(expectedRegistry);
  if (!expectedHost) {
    errors.push(
      'PUBLISH_NAMES.json#registry is missing or unparseable — the canonical ' +
        'publish registry must be recorded so the gate can detect registry drift ' +
        '(FWA-BV-SDK-01).',
    );
  }

  const actualRegistry = pkg.publishConfig && pkg.publishConfig.registry;
  if (typeof actualRegistry !== 'string' || actualRegistry.trim() === '') {
    errors.push(
      'package.json#publishConfig.registry is missing — without a pinned ' +
        'registry the package can publish to an attacker-controlled or default ' +
        'endpoint (FWA-BV-SDK-01).',
    );
  } else if (expectedHost) {
    const actualHost = normalizeRegistryHost(actualRegistry);
    if (actualHost !== expectedHost) {
      errors.push(
        `registry-drift: package.json#publishConfig.registry "${actualRegistry}" ` +
          `(host "${actualHost ?? '<unparseable>'}") does not match the canonical ` +
          `registry "${expectedRegistry}" (host "${expectedHost}") recorded in ` +
          `PUBLISH_NAMES.json. Repointing the publish registry is rejected ` +
          `(FWA-BV-SDK-01).`,
      );
    }
  }

  // PROVENANCE (2026-08-01). The published 0.2.0 states its source is
  // the `citrate-ai` GitHub owner — which does not exist. The gate already
  // refused a drifted *registry*; it had nothing to say about a drifted *source*,
  // so the package shipped to npm advertising a 404 as its provenance. A consumer
  // who cannot reach the source cannot audit what they installed, which is the one
  // thing a supply-chain gate exists to preserve.
  const expectedRepo = reservation.sourceRepo;
  if (typeof expectedRepo !== 'string' || expectedRepo.trim() === '') {
    errors.push(
      'PUBLISH_NAMES.json#sourceRepo is missing — the canonical source repo must ' +
        'be recorded so the gate can detect provenance drift.',
    );
  } else {
    const repoUrl = pkg.repository && pkg.repository.url;
    if (typeof repoUrl !== 'string' || repoUrl.trim() === '') {
      errors.push(
        'package.json#repository.url is missing — a published package with no ' +
          'stated source cannot be audited by the people who install it.',
      );
    } else if (!repoUrl.includes(`github.com/${expectedRepo}`)) {
      errors.push(
        `provenance-drift: package.json#repository.url "${repoUrl}" does not point ` +
          `at the canonical source "github.com/${expectedRepo}" recorded in ` +
          `PUBLISH_NAMES.json#sourceRepo. Publishing a package whose stated origin ` +
          `is wrong (or nonexistent) ships an unauditable artifact.`,
      );
    }

    // A `directory` field is a monorepo-era artifact. This repo IS the package
    // root; a leftover subpath sends tooling to a directory that does not exist.
    if (pkg.repository && pkg.repository.directory != null) {
      errors.push(
        `provenance-drift: package.json#repository.directory ` +
          `"${pkg.repository.directory}" is set, but this repo is the package root. ` +
          `That subpath is a leftover from the pre-split monorepo layout.`,
      );
    }
  }

  // Publishable sub-packages (2026-09-24 pre-bounty audit, PBA-L6-004): the
  // compat shim shipped to npm with no repository because only the root
  // manifest was checked. Every non-private package under compat/ or packages/
  // must name the canonical source and its own subpath as `directory`.
  if (typeof expectedRepo === 'string' && expectedRepo.trim() !== '') {
    for (const group of ['compat', 'packages']) {
      const groupDir = join(root, group);
      if (!existsSync(groupDir)) continue;
      for (const entry of readdirSync(groupDir, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        const manifest = join(groupDir, entry.name, 'package.json');
        if (!existsSync(manifest)) continue;
        const sub = JSON.parse(readFileSync(manifest, 'utf8'));
        if (sub.private === true) continue;
        const rel = `${group}/${entry.name}`;
        const subUrl = sub.repository && sub.repository.url;
        if (typeof subUrl !== 'string' || !subUrl.includes(`github.com/${expectedRepo}`)) {
          errors.push(
            `provenance-drift: ${rel}/package.json#repository.url must point at ` +
              `github.com/${expectedRepo} (got ${JSON.stringify(subUrl ?? null)}).`,
          );
        }
        if (!sub.repository || sub.repository.directory !== rel) {
          errors.push(
            `provenance-drift: ${rel}/package.json#repository.directory must be "${rel}".`,
          );
        }
      }
    }
  }

  return errors;
}

// Run directly (CLI / CI), not when imported by the jest test.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  // CITRATE_GATE_ROOT lets the test harness point the gate at a fixture repo
  // root. Unset in CI / normal use, so the canonical repoRoot is checked.
  const root = process.env.CITRATE_GATE_ROOT || repoRoot;
  const errors = checkPublishNames(root);
  if (errors.length > 0) {
    console.error('FWA-C12-01 publish-name gate FAILED:');
    for (const e of errors) console.error('  - ' + e);
    process.exit(1);
  }
  console.log('FWA-C12-01 publish-name gate PASSED.');
}
