---
created: 2026-10-05T00:00:00Z
branch: fix/windows-integration-test-script
author: OpenCode
status: ready_for_review
sprint: sdk-js-windows-integration-test-script
---

# SDK JS Windows integration test script fix

[citrate-sdk-js issue #28](https://github.com/CitrateNetwork/citrate-sdk-js/issues/28)
owns the scope and acceptance criteria. Under Rule 4, this sprint file owns execution status.
The failure is reproduced from `origin/main`: `npm run test:integration:testnet` exits in
`cmd.exe` because the POSIX-style `CITRATE_RPC_URL=...` prefix is treated as a command.

Verification completed on Windows:

- The focused cross-platform runner suite passed 4 tests.
- Both integration npm scripts reached Jest and discovered the two intended integration suites.
- A live invocation collected 33 tests: 27 passed, 2 skipped, and 4 existing integration
  assertions failed against the service already listening on `localhost:8545` (two unfunded
  accounts and two stale expected errors). This change does not alter those tests or SDK behavior.
- The full unit suite passed 32 suites and 520 tests.
- Lint completed with zero errors, the SDK build and publish build passed, the publish-name and
  packed-artifact key-share gates passed, and the production dependency audit found no
  vulnerabilities.
