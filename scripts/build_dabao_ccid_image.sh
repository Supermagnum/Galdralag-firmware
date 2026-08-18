#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build a Dabao Xous image with:
#   - xous-core `dabao-ccid` (usb-bao1x + ccid-openpgp; no PDDB / no SPI flash)
#   - out-of-tree galdralag-service (OpenPGP APDU dispatch) as a boot *service*
#
# Does not write into the xous-core tree. Only runs `cargo xtask` there.
#
# Plain `cargo xtask dabao-ccid` WITHOUT a cratespec is transport-only (inline
# ATR / GetSlotStatus) and will never reach gpg --card-status APDUs.
#
# Usage:
#   scripts/build_dabao_ccid_image.sh
#   XOUS_CORE=/path/to/xous-core scripts/build_dabao_ccid_image.sh
#   scripts/build_dabao_ccid_image.sh --no-verify
#   scripts/build_dabao_ccid_image.sh --skip-preflight
#
# Preflight is the first step (unless --skip-preflight). A stale nested
# Galdralag-firmware/xous-core checkout would otherwise compile galdralag-service
# against old HAL/IPC and still let `cargo xtask dabao-ccid` succeed as a
# transport-only-looking image. Fail fast instead.
#
# Fail-fast check (manual): with nested ./xous-core as a real old checkout
# (not a symlink to the CCID sibling), run this script without
# --skip-preflight. It must exit non-zero at "xous-core preflight" and must
# not print "Build galdralag-service".

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
      sed -n '2,22p' "$0"
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

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

need_cmd cargo
need_cmd git

[[ -d "$GALDRA_ROOT" ]] || fail "Galdralag root not found: $GALDRA_ROOT"
[[ -d "$XOUS_CORE" ]] || fail "xous-core not found: $XOUS_CORE (set XOUS_CORE=...)"

# Must run before any cargo build: path deps use ./xous-core; a stale nested
# tree would produce an ELF that cannot speak CcidRxDeferred while dabao-ccid
# still succeeds as transport-only.
if [[ "$SKIP_PREFLIGHT" -eq 0 ]]; then
  step "xous-core preflight"
  XOUS_CORE="$XOUS_CORE" "$SCRIPT_DIR/check_xous_core_preflight.sh"
fi

step "Build galdralag-service (board-dabao)"
(
  cd "$GALDRA_ROOT"
  cargo run -p xtask -- build-galdralag-xous release --board dabao
) || fail "build-galdralag-xous dabao failed"

SPEC="$(
  cd "$GALDRA_ROOT"
  cargo run -p xtask --quiet -- print-galdralag-xous-cratespec release
)" || fail "print-galdralag-xous-cratespec failed"
echo "Cratespec: $SPEC"

# dabao-ccid registers positional cratespecs as Flash boot services (not apps).
IMAGE_VERB="dabao-ccid"

step "Build xous-core image ($IMAGE_VERB + galdralag-service)"
echo "Working directory: $XOUS_CORE"
CMD=(cargo xtask "$IMAGE_VERB" "$SPEC")
CMD+=("${EXTRA_XOUS_FLAGS[@]}")
printf 'Full command: '; printf '%q ' "${CMD[@]}"; echo

(
  cd "$XOUS_CORE"
  "${CMD[@]}"
) || fail "xous-core $IMAGE_VERB build failed"

UF2_DIR="$XOUS_CORE/target/riscv32imac-unknown-xous-elf/release"
step "UF2 artifacts under $UF2_DIR"
missing=0
for f in loader.uf2 xous.uf2; do
  if [[ -f "$UF2_DIR/$f" ]]; then
    echo "OK  $UF2_DIR/$f"
  else
    echo "MISSING  $UF2_DIR/$f" >&2
    missing=1
  fi
done
# apps.uf2 may be absent on some dabao layouts; do not hard-fail if missing.
if [[ -f "$UF2_DIR/apps.uf2" ]]; then
  echo "OK  $UF2_DIR/apps.uf2"
else
  echo "NOTE: apps.uf2 not present (optional for this recipe)"
fi
[[ "$missing" -eq 0 ]] || fail "required UF2 missing; search: find $XOUS_CORE/target -name '*.uf2'"

echo ""
echo "Done. Flash loader.uf2 + xous.uf2 via boot1 (PROG + BAOCHIP volume)."
echo "Host: add libccid Info.plist VID:PID 1D50:6197 before pcscd (see docs/HARDWARE_BRINGUP_TEST_PLAN.md)."
echo "Plain dabao-ccid without cratespec is transport-only — this build includes galdralag-service."
