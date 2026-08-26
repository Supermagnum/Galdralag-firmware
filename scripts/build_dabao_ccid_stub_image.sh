#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build dabao-ccid with galdralag-stub (minimal XfrBlock/SELECT handler) instead of
# galdralag-service. Use to isolate transport vs full OpenPGP handler (Phase 2 bring-up).
#
# Usage:
#   scripts/build_dabao_ccid_stub_image.sh
#   scripts/build_dabao_ccid_stub_image.sh --no-verify

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GALDRA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_SIBLING="$(cd "${GALDRA_ROOT}/.." && pwd)/xous-core"
XOUS_CORE="${XOUS_CORE:-$DEFAULT_SIBLING}"
NO_VERIFY=0
SKIP_PREFLIGHT=0
EXTRA_XOUS_FLAGS=()

for arg in "$@"; do
  case "$arg" in
    --no-verify) NO_VERIFY=1 ;;
    --skip-preflight) SKIP_PREFLIGHT=1 ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

if [[ "$NO_VERIFY" -eq 1 ]]; then
  EXTRA_XOUS_FLAGS+=(--no-verify)
fi

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

step() {
  echo ""
  echo "======================================================================"
  echo "== $*"
  echo "======================================================================"
}

[[ -d "$GALDRA_ROOT" ]] || fail "Galdralag root not found: $GALDRA_ROOT"
[[ -d "$XOUS_CORE" ]] || fail "xous-core not found: $XOUS_CORE (set XOUS_CORE=...)"

if [[ "$SKIP_PREFLIGHT" -eq 0 ]]; then
  step "xous-core preflight"
  XOUS_CORE="$XOUS_CORE" "$SCRIPT_DIR/check_xous_core_preflight.sh"
fi

step "Build galdralag-stub"
(
  cd "$GALDRA_ROOT"
  cargo run -p xtask -- build-galdralag-stub release
) || fail "build-galdralag-stub failed"

SPEC="$(
  cd "$GALDRA_ROOT"
  cargo run -p xtask --quiet -- print-galdralag-stub-cratespec release
)" || fail "print-galdralag-stub-cratespec failed"
echo "Cratespec: $SPEC"

step "Build xous-core image (dabao-ccid + galdralag-stub)"
echo "Working directory: $XOUS_CORE"
CMD=(cargo xtask dabao-ccid "$SPEC")
CMD+=("${EXTRA_XOUS_FLAGS[@]}")
printf 'Full command: '; printf '%q ' "${CMD[@]}"; echo

(
  cd "$XOUS_CORE"
  "${CMD[@]}"
) || fail "xous-core dabao-ccid build failed"

UF2_DIR="$XOUS_CORE/target/riscv32imac-unknown-xous-elf/release"
step "UF2 artifacts under $UF2_DIR"
for f in loader.uf2 xous.uf2; do
  [[ -f "$UF2_DIR/$f" ]] || fail "required UF2 missing: $UF2_DIR/$f"
  echo "OK  $UF2_DIR/$f"
done
if [[ -f "$UF2_DIR/apps.uf2" ]]; then
  echo "OK  $UF2_DIR/apps.uf2"
fi

echo ""
echo "Done. Flash loader.uf2 + xous.uf2; test with pcsc_scan then opensc-tool --info."
echo "This image uses galdralag-stub (SELECT + 9000), not galdralag-service."
