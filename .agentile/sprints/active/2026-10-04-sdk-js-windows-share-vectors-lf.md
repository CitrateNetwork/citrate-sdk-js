---
created: 2026-10-04T00:00:00Z
branch: fix/windows-share-vector-lf
author: OpenCode
status: ready_for_review
sprint: sdk-js-windows-share-vectors-lf
---

# SDK JS Windows shared-vector LF fix

[citrate-sdk-js issue #20](https://github.com/CitrateNetwork/citrate-sdk-js/issues/20)
owns the scope and acceptance criteria. Under Rule 4, this sprint file owns execution status:
the root cause is confirmed as checkout conversion under `core.autocrlf=true`. The fix pins
`tests/fixtures/share_guard_vectors.json` to LF checkout bytes and adds a regression test for
both the Git attribute and the absence of carriage-return bytes.

Verification completed on Windows:

- A fresh clone configured with `core.autocrlf=true` retained the canonical 16,869-byte fixture,
  with SHA-256 `674d35d72f4fca132e59e325efec3a61fcb4cbe7d6cfc5afd85d1821afcf884f`,
  1,078 LF bytes, and zero CRLF pairs.
- The targeted regression suite passed 96 tests.
- The full unit suite passed 31 suites and 517 tests.
- Lint completed with zero errors, the SDK and publish builds passed, the publish-name gate
  passed, and `npm audit --audit-level=high --omit=dev` reported zero vulnerabilities.
