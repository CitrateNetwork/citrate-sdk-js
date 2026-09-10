---
created: 2026-06-21T00:00:00Z
branch: remediation/fwa-2026-06
author: claude-opus-4-8 (RM-SUPPLY remediation agent)
status: complete
audit_id: 2026-06-20-federation-wide-audit
chunk: FWA-C12
standard: Agentile-Audit Standard v0.2
---

# RM-SUPPLY remediation log — `citrate-sdk-js`

Close-gate protocol: RED → FIX → SWEEP → TRIPWIRE → MUTATION → RECORD.

## FWA-C12-01 (HIGH) — dependency-confusion: unscoped `citrate-js` + manifest publish-name drift

**Root cause.** `citrate-sdk-js/package.json#name = "citrate-js"` publishes to
public npmjs.org **unscoped** with **no `publishConfig`** → ambiguous default
publish target, squattable name (prior WEB-5, un-closed). The federation manifest
recorded `@citratenetwork/sdk` — a name this repo never publishes — so any
defensive registration / verification job targeted a phantom string while the
real `citrate-js` stayed open.

**Decision (smallest robust).** Keep the canonical published name `citrate-js`
(already shipped at v0.2.0; scoping would be a breaking rename for consumers and
the docs reference it as canonical). Add `publishConfig` (explicit `access` +
registry), reserve the real name in-repo, and reconcile the federation manifest
to the real name. A name-drift CI gate makes future drift fail closed.

**RED → GREEN evidence.**
- Check: `tests/unit/rm_supply_c12_01_publish_names.test.ts` (jest) and the CLI
  gate `scripts/check-publish-names.mjs`.
- RED (pre-fix): `npx jest tests/unit/rm_supply_c12_01_publish_names.test.ts`
  → 1 failed (`package.json#publishConfig.access` undefined); `node
  scripts/check-publish-names.mjs` → EXIT 1 ("publishConfig.access is missing").
- GREEN (post-fix): jest 3/3 pass; script → EXIT 0 ("gate PASSED").
- Full unit suite after fix: **9 suites / 72 tests pass** (no regression).

**Files + LOC.**
- `package.json:5-8` — added `"publishConfig": { "access": "public", "registry": "https://registry.npmjs.org/" }`.
- `package.json:21-22` — added `verify:publish-names` script; wired it into
  `prepublishOnly` so a publish is blocked on drift.
- `PUBLISH_NAMES.json` (new) — in-repo reservation mirror of the federation
  manifest `[repos.citrate-sdk-js].publishes`; `reserved = ["citrate-js"]`.
- `scripts/check-publish-names.mjs` (new) — the gate logic (name ∈ reserved +
  publishConfig present).
- `tests/unit/rm_supply_c12_01_publish_names.test.ts` (new) — jest red→green gate.
- `.github/workflows/ci.yml` — new `publish-names` CI job runs the gate.

**Test/check delta.** +1 jest suite (3 tests), +1 CLI gate, +1 CI job. No existing
test weakened.

**Tripwire (permanent).** `publish-names` CI job + the `prepublishOnly` hook: any
rename of `package.json#name` away from `PUBLISH_NAMES.json`, or dropping
`publishConfig`, fails the build and blocks publish. Logic-level (manifest +
JSON), so this is the durable gate.

**Mutation.** Not applicable — the change is package metadata + a manifest/JSON
consistency gate, not algorithmic code. The red→green drift test (flip the name
or remove publishConfig ⇒ fail) is the logic-level mutation equivalent and is
demonstrated above (RED state observed before fix).

**Actual-vs-manifest publish-name reconciliation.**

| Repo | Real published name (file:line) | Manifest `publishes` BEFORE | Manifest `publishes` AFTER |
|------|---------------------------------|------------------------------|-----------------------------|
| citrate-sdk-js | `citrate-js` (`package.json:2`) | `@citratenetwork/sdk` (phantom) | `citrate-js` ✓ |
| citrate-sdk-python | `citrate-ai-sdk` (`pyproject.toml:15`) | `citrate-sdk` (phantom) | `citrate-ai-sdk` ✓ |
| citrate-sdk-marketplace | `@citratenetwork/marketplace-sdk` (`package.json:2`) | `@citratenetwork/marketplace-sdk` ✓ | unchanged ✓ |

Manifest edits are in the `citrate-federation` repo (`manifest.toml:200,208`),
branch `remediation/fwa-2026-06`. After this remediation, the in-repo reservation
(`PUBLISH_NAMES.json`), the manifest `publishes`, and `package.json#name` all
agree on `citrate-js`.

## SWEEP — every published package across the SDK family

| Package (repo) | Registry | Scoped? | publishConfig? | Action |
|----------------|----------|---------|----------------|--------|
| `citrate-js` (citrate-sdk-js) | public npmjs.org | no | **added** | FIXED here (this branch) |
| `citrate-ai-sdk` (citrate-sdk-python) | PyPI | n/a (PyPI has no scopes) | n/a | Manifest name reconciled (federation branch). **Defensive PyPI reservation of `citrate-ai-sdk` still required off-repo.** Out of this repo's scope. |
| `@citratenetwork/marketplace-sdk` (citrate-sdk-marketplace) | GitHub Packages (registry-pinned `.npmrc`) | **yes** | yes (`package.json:47-49`) | LOW — no action. |

## NEEDS-REPRO (cannot be proven from code — registry occupancy is offline)

Defensive ownership on the public registries is an off-repo operational task and
is NOT proven by a check here. In priority order, own / reserve:
1. npm `citrate-js` (primary)
2. npm scopes `@citratenetwork` and `@citrate`
3. PyPI `citrate-ai-sdk`
4. npm `citrate-ai-sdk`, PyPI `citrate-js` (cross-ecosystem squat surface)

These are marked **NEEDS-REPRO**: the in-repo gate guarantees the manifest and
package name never drift apart again, but it cannot assert registry ownership.

## CODE-QUALITY
Gate is dependency-free (`node:fs`/`node:path` only), runs in both jest and CI,
and shares one reservation file with the federation manifest — single source of
truth, no copy that can silently rot. `prepublishOnly` makes the gate
fail-closed at publish time, not just in CI.

## DOCUMENTATION
`PUBLISH_NAMES.json` carries an inline `_comment` pointing at the federation
manifest and the gate; `scripts/check-publish-names.mjs` and the jest test both
document the WEB-5 / FWA-C12-01 rationale in their headers; this log records the
full actual-vs-manifest reconciliation table.
