#!/usr/bin/env bash
# Run cargo-vet against this workspace (Lot 8 supply-chain).
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v cargo-vet >/dev/null 2>&1; then
  echo "cargo-vet not installed. Try: cargo install cargo-vet --locked" >&2
  exit 1
fi

echo "==> cargo vet --locked"
cargo vet --locked "$@"
