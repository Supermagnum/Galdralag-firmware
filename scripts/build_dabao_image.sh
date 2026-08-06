#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build a flashable Baochip Xous image that includes:
#   - xous-core usb-bao1x with ccid-openpgp
#   - Galdralag galdralag-service (CCID OpenPGP handler)
#
# IMPORTANT (from xous-core xtask sources — do not guess):
#   - `cargo xtask dabao` does NOT enable `ccid-openpgp` and does not include
#     the `pddb` service (xtask/src/main.rs dabao arm).
#   - Positional cratespecs on `dabao` are registered as *apps*, not services.
#   - The supported CCID image verb is `baosec-ccid` (baosec_common + feature
#     ccid-openpgp). Galdralag docs also register via `baosec` + cratespec
#     (services/galdralag/README.md).
#   - This script therefore builds `baosec-ccid` + galdralag-service cratespec.
#     See TODO(DABAO) below if a true dabao+ccid recipe is added upstream later.
#
# Usage:
#   scripts/build_dabao_image.sh
#   XOUS_CORE=/path/to/xous-core scripts/build_dabao_image.sh
#   scripts/build_dabao_image.sh --no-verify   # skip crates.io consistency check

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GALDRA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
XOUS_CORE="${XOUS_CORE:-/mnt/2e9a1e9f-2097-408c-ab9a-a01b32f11d28/github-projects/xous-core}"
NO_VERIFY=0
EXTRA_XOUS_FLAGS=()

for arg in "$@"; do
  case "$arg" in
    --no-verify) NO_VERIFY=1 ;;
    -h|--help)
      sed -n '2,24p' "$0"
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
  command -v "$1" >/dev/null 2>&1 || fail "required command not found on PATH: $1"
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
step "Check prerequisites"

need_cmd cargo
need_cmd rustc
need_cmd rustup
need_cmd git
need_cmd pkg-config
need_cmd python3

[[ -d "$GALDRA_ROOT" ]] || fail "Galdralag-firmware root not found: $GALDRA_ROOT"
[[ -d "$XOUS_CORE" ]] || fail "xous-core root not found: $XOUS_CORE (set XOUS_CORE=...)"
[[ -f "$GALDRA_ROOT/xtask/src/main.rs" ]] || fail "missing Galdralag xtask"
[[ -f "$XOUS_CORE/xtask/src/main.rs" ]] || fail "missing xous-core xtask"
[[ -d "$GALDRA_ROOT/xous-core/imports/getrandom" ]] \
  || fail "bundled xous-core getrandom patch missing: $GALDRA_ROOT/xous-core/imports/getrandom"

# System packages (from xous-core .github/workflows/build.yml / ccid-ci.yml).
if ! pkg-config --exists xkbcommon 2>/dev/null; then
  fail "libxkbcommon development package missing (pkg-config xkbcommon failed).
On Debian/Ubuntu: sudo apt install -y libxkbcommon-dev"
fi

# Galdralag rust-toolchain.toml pins channel=stable and
# targets = ["riscv32imac-unknown-none-elf"] (firmware triple).
# Xous userland needs riscv32imac-unknown-xous-elf via betrusted-io toolkit.
if [[ -f "$GALDRA_ROOT/rust-toolchain.toml" ]]; then
  echo "Galdralag rust-toolchain.toml:"
  cat "$GALDRA_ROOT/rust-toolchain.toml"
else
  echo "WARNING: Galdralag rust-toolchain.toml not found"
fi

# xous-core has no rust-toolchain.toml in-tree (verified absent at repo root).
# Toolchain must match a betrusted-io/rust release so install-toolkit works.
if [[ ! -f "$XOUS_CORE/rust-toolchain.toml" ]]; then
  echo "NOTE: xous-core has no rust-toolchain.toml; host rustc must match toolkit (cargo xtask install-toolkit)."
fi

echo "Host rustc: $(rustc --version)"

# Ed25519 developer signing keys (xtask/src/builder.rs defaults; help text in main.rs).
DEV_KEY="$XOUS_CORE/devkey/dev.key"
[[ -f "$DEV_KEY" ]] || fail "missing developer signing key: $DEV_KEY
(see xous-core/devkey/README.md — shipped Ed25519 dev key for non-production images)"

# Custom Xous libstd target (install-toolkit downloads matching sysroot).
step "Ensure Xous RISC-V toolkit (riscv32imac-unknown-xous-elf)"
(
  cd "$XOUS_CORE"
  cargo xtask install-toolkit --force --no-verify
) || fail "cargo xtask install-toolkit failed in $XOUS_CORE"

# Kernel / baremetal target used by bao1x builds (xtask TARGET_TRIPLE_RISCV32_KERNEL).
if ! rustup target list --installed | grep -qx 'riscv32imac-unknown-none-elf'; then
  echo "Adding rustup target riscv32imac-unknown-none-elf ..."
  rustup target add riscv32imac-unknown-none-elf \
    || fail "rustup target add riscv32imac-unknown-none-elf failed"
fi

# TODO(build-std): xtask sources under xtask/src/ do not mention -Zbuild-std.
# The xous-elf target relies on the custom toolkit sysroot from install-toolkit.
# If a future upstream build requires -Zbuild-std, document it here.

# ---------------------------------------------------------------------------
# Build galdralag-service ELF
# ---------------------------------------------------------------------------
# Standalone services/galdralag is its own Cargo workspace (README.md). The
# shipped manifest is incomplete vs full xous-core xtask for xous-elf baosec:
#
#   1. blitstr2 glyphs() needs feature "bao1x" on target_os=xous, but
#      bao1x-hal board-baosec only enables blitstr2/board-baosec via ux-api
#      (NOT blitstr2/bao1x). Full xtask pushes "bao1x" onto services
#      (xous-core xtask/src/builder.rs).
#   2. pddb with only ["mbbb"] pulls keystore-api without gen1/gen2, so
#      keystore-api/src/common.rs fails on TOTAL_CHECKSUMS. board-baosec
#      enables gen2.
#   3. [patch.crates-io] lacks getrandom -> xous-core/imports/getrandom
#      (xous-core Cargo.toml [patch.crates-io.getrandom]); crates.io
#      getrandom does not support target_os=xous. Cargo only applies a path
#      patch when versions match; lock uses 0.2.17, path crate is 0.2.12.
#
# Temporary Cargo.toml / Cargo.lock / getrandom version patches restored on
# exit. No .rs / xtask changes.
#
# TODO(galdralag-manifest): Permanent fixes belong in
#   services/galdralag/Cargo.toml (blitstr2 bao1x, pddb board-baosec,
#   getrandom patch + matching version). Then drop workarounds below.
# TODO(blitstr2-features): Same as (1) — prefer upstream ux-api/bao1x-hal.
# TODO(baochip-openpgp-xous): After manifest workarounds, xous-elf build still
#   fails in crates/baochip-openpgp/src/xous_impl.rs (OnceLock<Rc<...>> needs
#   Sync; OpenPgpVaultBackend::new/open expect fn() not capturing closures).
#   Fixing that requires Rust source edits (forbidden for this task).
GALDRALAG_MANIFEST="${GALDRA_ROOT}/services/galdralag/Cargo.toml"
GALDRALAG_LOCK="${GALDRA_ROOT}/services/galdralag/Cargo.lock"
GALDRALAG_GETRANDOM_TOML="${GALDRA_ROOT}/xous-core/imports/getrandom/Cargo.toml"
GALDRALAG_MANIFEST_BACKUP=""
GALDRALAG_LOCK_BACKUP=""
GALDRALAG_GETRANDOM_BACKUP=""
restore_galdralag_manifest() {
  if [[ -n "${GALDRALAG_MANIFEST_BACKUP}" && -f "${GALDRALAG_MANIFEST_BACKUP}" ]]; then
    mv -f "${GALDRALAG_MANIFEST_BACKUP}" "${GALDRALAG_MANIFEST}"
    GALDRALAG_MANIFEST_BACKUP=""
  fi
  if [[ -n "${GALDRALAG_LOCK_BACKUP}" && -f "${GALDRALAG_LOCK_BACKUP}" ]]; then
    mv -f "${GALDRALAG_LOCK_BACKUP}" "${GALDRALAG_LOCK}"
    GALDRALAG_LOCK_BACKUP=""
  fi
  if [[ -n "${GALDRALAG_GETRANDOM_BACKUP}" && -f "${GALDRALAG_GETRANDOM_BACKUP}" ]]; then
    mv -f "${GALDRALAG_GETRANDOM_BACKUP}" "${GALDRALAG_GETRANDOM_TOML}"
    GALDRALAG_GETRANDOM_BACKUP=""
  fi
}
trap restore_galdralag_manifest EXIT

apply_galdralag_xous_manifest_workarounds() {
  local marker='GALDRALAG_XOUS_BUILD_WORKAROUND'
  if grep -q "${marker}" "${GALDRALAG_MANIFEST}"; then
    echo "NOTE: ${GALDRALAG_MANIFEST} already contains ${marker}"
    return 0
  fi
  GALDRALAG_MANIFEST_BACKUP="$(mktemp "${TMPDIR:-/tmp}/galdralag-Cargo.toml.XXXXXX")"
  cp -a "${GALDRALAG_MANIFEST}" "${GALDRALAG_MANIFEST_BACKUP}"
  if [[ -f "${GALDRALAG_LOCK}" ]]; then
    GALDRALAG_LOCK_BACKUP="$(mktemp "${TMPDIR:-/tmp}/galdralag-Cargo.lock.XXXXXX")"
    cp -a "${GALDRALAG_LOCK}" "${GALDRALAG_LOCK_BACKUP}"
  fi
  GALDRALAG_GETRANDOM_BACKUP="$(mktemp "${TMPDIR:-/tmp}/getrandom-Cargo.toml.XXXXXX")"
  cp -a "${GALDRALAG_GETRANDOM_TOML}" "${GALDRALAG_GETRANDOM_BACKUP}"
  # Align path-crate version with services/galdralag/Cargo.lock (0.2.17).
  sed -i 's/^version = "0\.2\.12"/version = "0.2.17"/' "${GALDRALAG_GETRANDOM_TOML}" \
    || fail "failed to bump getrandom path-crate version for Cargo patch match"

  python3 - "$GALDRALAG_MANIFEST" "$marker" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
marker = sys.argv[2]
text = path.read_text()

old_pddb = 'pddb = { path = "../../xous-core/services/pddb", default-features = false, features = ["mbbb"] }'
new_pddb = 'pddb = { path = "../../xous-core/services/pddb", default-features = false, features = ["mbbb", "board-baosec"] }'
if old_pddb not in text:
    sys.exit(f"ERROR: expected pddb line not found in {path}")
text = text.replace(old_pddb, new_pddb, 1)

needle = 'bao1x-hal = { path = "../../xous-core/libs/bao1x-hal", features = ["std", "board-baosec"] }'
if needle not in text:
    sys.exit(f"ERROR: expected bao1x-hal line not found in {path}")
insert = (
    needle
    + f"\n# {marker} (injected by scripts/build_dabao_image.sh; restored on exit)\n"
    + 'blitstr2 = { path = "../../xous-core/libs/blitstr2", features = ["bao1x", "board-baosec"] }\n'
)
text = text.replace(needle, insert, 1)

patch_anchor = "[patch.crates-io]\n"
if patch_anchor not in text:
    sys.exit(f"ERROR: [patch.crates-io] missing in {path}")
if "getrandom" not in text.split("[patch.crates-io]", 1)[1]:
    text = text.replace(
        patch_anchor,
        patch_anchor
        + f"# {marker}\n"
        + 'getrandom = { path = "../../xous-core/imports/getrandom" }\n',
        1,
    )

path.write_text(text)
print(f"patched {path}")
PY

  echo "NOTE: temporarily patched ${GALDRALAG_MANIFEST} + getrandom version"
  echo "      see TODO(galdralag-manifest) / TODO(baochip-openpgp-xous)"
}

step "Build galdralag-service (Xous ELF)"
apply_galdralag_xous_manifest_workarounds
(
  cd "$GALDRA_ROOT"
  cargo run -p xtask -- build-galdralag-xous release
) || fail "build-galdralag-xous failed
See TODO(galdralag-manifest) and TODO(baochip-openpgp-xous).
Bundled tree: ${GALDRA_ROOT}/xous-core.
Known blocker after manifest workarounds: crates/baochip-openpgp/src/xous_impl.rs
(Sync/Send on OnceLock<Rc<...>>; fn() vs capturing closures) — needs Rust fixes."
restore_galdralag_manifest
trap - EXIT

step "Capture cratespec"
SPEC="$(
  cd "$GALDRA_ROOT"
  cargo run -p xtask --quiet -- print-galdralag-xous-cratespec release
)" || fail "print-galdralag-xous-cratespec failed"

[[ -n "$SPEC" ]] || fail "empty cratespec"
case "$SPEC" in
  galdralag-service:/*) ;;
  *) fail "unexpected cratespec format (expected galdralag-service:/abs/path): $SPEC" ;;
esac
ELF_PATH="${SPEC#galdralag-service:}"
[[ -f "$ELF_PATH" ]] || fail "cratespec ELF missing on disk: $ELF_PATH"
echo "Cratespec: $SPEC"

# ---------------------------------------------------------------------------
# xous-core image build
# ---------------------------------------------------------------------------
# TODO(DABAO): There is no supported `cargo xtask dabao ...` recipe that enables
# ccid-openpgp and registers a positional cratespec as a *service*. Using
# baosec-ccid instead (xtask/src/main.rs baosec-ccid + baosec_common).
IMAGE_VERB="baosec-ccid"

step "Build xous-core image ($IMAGE_VERB + galdralag-service)"
CMD=(cargo xtask "$IMAGE_VERB" "$SPEC")
CMD+=("${EXTRA_XOUS_FLAGS[@]}")

echo "Working directory: $XOUS_CORE"
echo -n "Full command: "
printf '%q ' "${CMD[@]}"
echo

(
  cd "$XOUS_CORE"
  "${CMD[@]}"
) || fail "xous-core image build failed"

# ---------------------------------------------------------------------------
# Locate UF2 artifacts
# ---------------------------------------------------------------------------
# README-baochip.md: target/riscv32imac-unknown-[xous|none]-elf/release/
# tools-bao/commands/artifacts.py: .../riscv32imac-unknown-xous-elf/release/{loader,xous,apps}.uf2
UF2_DIR="$XOUS_CORE/target/riscv32imac-unknown-xous-elf/release"
LOADER_UF2="$UF2_DIR/loader.uf2"
XOUS_UF2="$UF2_DIR/xous.uf2"
APPS_UF2="$UF2_DIR/apps.uf2"

step "UF2 artifacts"
missing=0
for f in "$LOADER_UF2" "$XOUS_UF2" "$APPS_UF2"; do
  if [[ -f "$f" ]]; then
    echo "OK  $f"
  else
    echo "MISSING  $f" >&2
    missing=1
  fi
done
if [[ "$missing" -ne 0 ]]; then
  # TODO(UF2-paths): If baosec-ccid places UF2s under a different directory after
  # an upstream change, update UF2_DIR. Also check none-elf for bootloader-only builds.
  fail "one or more UF2 artifacts missing under $UF2_DIR
Also search: find $XOUS_CORE/target -name '*.uf2'"
fi

# ---------------------------------------------------------------------------
# Flash summary (README-baochip.md)
# ---------------------------------------------------------------------------
step "Flash summary (from README-baochip.md)"
cat <<EOF
Artifacts (copy all three on first flash):
  $LOADER_UF2
  $XOUS_UF2
  $APPS_UF2

PROG / mass-storage sequence (README-baochip.md):
  1. Hold PROG while plugging USB — device enumerates as volume label BAOCHIP.
  2. Copy loader.uf2, xous.uf2, and apps.uf2 onto the BAOCHIP volume.
  3. Cleanly unmount / sync the drive.
  4. Press PROG again to run the program.

Serial console alternative after UF2 copy (Galdralag README / dabao issues):
  - boot1 USB serial at 1_000_000 baud (e.g. screen /dev/ttyACM0 1000000)
  - Type: boot
  - Console disconnect on reboot is expected.

Board note: this image is baosec-ccid (board-baosec), not the minimal dabao
service set. Hardware without baosec swap/camera may still run if compatible;
TODO(DABAO): confirm on your Dabao silicon once an official dabao+ccid recipe exists.

Image verb used: $IMAGE_VERB
Cratespec:       $SPEC
EOF

step "DONE"
