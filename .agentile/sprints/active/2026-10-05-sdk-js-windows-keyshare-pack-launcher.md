---
created: 2026-10-05T00:00:00Z
branch: fix/windows-keyshare-pack-launcher
author: OpenCode
status: ready_for_review
sprint: sdk-js-windows-keyshare-pack-launcher
---

# SDK JS Windows keyshare pack launcher fix

[citrate-sdk-js issue #26](https://github.com/CitrateNetwork/citrate-sdk-js/issues/26)
owns the scope and acceptance criteria. Under Rule 4, this sprint file owns execution status.
The failure is reproduced from `origin/main`: the packed-artifact tripwire exits at
`spawnSync npm ENOENT` on Windows before any PBA-L4-001 assertions execute.

Verification completed on Windows:

- The focused npm invocation regression test passed 4 tests.
- `node scripts/check-keyshare-pack.mjs` passed after `npm run build:publish`, proving the
  packed-artifact PBA-L4-001 tripwire now runs on Windows.
- The full unit suite passed 32 suites and 520 tests.
- Lint completed with zero errors, the SDK build and publish build passed, the publish-name gate
  passed, and `npm audit --audit-level=high --omit=dev` reported zero vulnerabilities.
