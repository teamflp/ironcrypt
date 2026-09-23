#!/usr/bin/env bash
# Generate a CycloneDX SBOM for IronCrypt (requires `cargo-cyclonedx`).
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
  echo "Install: cargo install cargo-cyclonedx" >&2
  exit 1
fi
mkdir -p target/sbom
cargo cyclonedx -f json --output-cdx target/sbom/ironcrypt.cdx.json
echo "Wrote target/sbom/ironcrypt.cdx.json"
