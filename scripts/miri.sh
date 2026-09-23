#!/usr/bin/env bash
# Run Miri on IronCrypt lib unit tests that are Miri-safe (Lot 8+).
set -euo pipefail
cd "$(dirname "$0")/.."

TOOLCHAIN="${MIRI_TOOLCHAIN:-nightly}"

echo "==> rustup component add miri ($TOOLCHAIN)"
rustup component add miri --toolchain "$TOOLCHAIN"

# cargo test accepts a single filter; run each module separately.
# Skip tests that need OS RNG / networking / FS heavily when MIRIFLAGS set.
MODULES=(
  crypto_allowlist::
  envelope::
  context::
  audit::
  resilience::
  limits::
  key_lifecycle::
  dual_control::
)

echo "==> cargo +$TOOLCHAIN miri test --lib (filtered modules)"
for mod in "${MODULES[@]}"; do
  echo "---- miri: $mod"
  cargo "+$TOOLCHAIN" miri test --lib "$mod" "$@"
done
