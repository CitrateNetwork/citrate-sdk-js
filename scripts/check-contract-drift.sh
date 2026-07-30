#!/usr/bin/env bash
# LOCAL contract-drift check — no GitHub Actions, no token required.
#
# Verifies this SDK's vendored src/generated/federation-contract.json still
# matches the canonical federation intermediate
# (citrate-federation/contract/federation-contract.json), which is itself gated
# fresh against citrate-chain by federation's contract-artifact-drift workflow.
# Run before pushing/merging and after every re-roll while org CI is down.
#
#   bash scripts/check-contract-drift.sh
#
# Exit 1 on drift. Local mirror of the `contract-drift` job in
# .github/workflows/ci.yml (CL-C2 / SW-089).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CANONICAL="$HERE/../citrate-federation/contract/federation-contract.json"

if [ ! -f "$CANONICAL" ]; then
  echo "[contract-drift] federation sibling not found at $CANONICAL"
  echo "  Ensure citrate-federation is a sibling of this repo under citrate-labs/."
  exit 2
fi

npm run --silent verify:contract
