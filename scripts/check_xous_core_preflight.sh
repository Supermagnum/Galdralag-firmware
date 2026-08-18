#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Fail loudly if the configured xous-core tree is not the CCID/OpenPGP branch
# Galdralag expects for usb-bao1x IPC (opcodes 640/642, feature ccid-openpgp).
#
# Does not modify xous-core. Read-only checks only.
#
# Usage:
#   scripts/check_xous_core_preflight.sh
#   XOUS_CORE=/path/to/xous-core scripts/check_xous_core_preflight.sh
#   cargo run -p xtask -- check-xous-core
#
# On failure, stderr states what is wrong, then a copy-pasteable
#   ln -sfn <sibling> ./xous-core
# and exits non-zero.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GALDRA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Sibling checkout is the default for image builds (not the nested path-dep tree).
DEFAULT_SIBLING="$(cd "${GALDRA_ROOT}/.." && pwd)/xous-core"
XOUS_CORE="${XOUS_CORE:-$DEFAULT_SIBLING}"
NESTED="${GALDRA_ROOT}/xous-core"

# Branch that carries Persona A CCID transport + CcidRxDeferred / CcidTx.
# Tracked upstream as https://github.com/betrusted-io/xous-core/pull/937
EXPECTED_BRANCH="${GALDRALAG_XOUS_BRANCH:-feature/usb-bao1x-ccid-openpgp}"

symlink_target() {
  # Prefer a tree that already passed CCID checks; never point at the nested checkout.
  local target="$XOUS_CORE"
  if [[ "$XOUS_CORE" == "$NESTED" ]]; then
    target="$DEFAULT_SIBLING"
  fi
  printf '%s' "$target"
}

print_fix() {
  local target
  target="$(symlink_target)"
  echo "" >&2
  echo "Fix (copy-paste from the Galdralag-firmware repository root):" >&2
  if [[ -e "$NESTED" && ! -L "$NESTED" ]]; then
    echo "  # ./xous-core is a real checkout, not a symlink; rename it first so ln does not nest:" >&2
    echo "  mv ./xous-core ./xous-core.stale-nested" >&2
  fi
  echo "  ln -sfn ${target} ./xous-core" >&2
  echo "" >&2
  echo "If image builds should use a different CCID tree:" >&2
  echo "  export XOUS_CORE=${target}" >&2
  echo "" >&2
  echo "Then re-run:" >&2
  echo "  cargo run -p xtask -- check-xous-core" >&2
}

fail() {
  echo "ERROR: $*" >&2
  print_fix
  exit 1
}

warn() {
  echo "WARNING: $*" >&2
}

check_tree() {
  local label="$1"
  local root="$2"
  local required="$3" # "required" | "optional"

  if [[ ! -d "$root" ]]; then
    if [[ "$required" == "required" ]]; then
      fail "xous-core at \`${root}\` (${label}) was not found.
Set XOUS_CORE to a checkout of branch ${EXPECTED_BRANCH}
(https://github.com/Supermagnum/xous-core/tree/${EXPECTED_BRANCH})."
    fi
    warn "$label missing ($root); skipped"
    return 0
  fi

  echo "Checking $label: $root"

  [[ -f "$root/xtask/src/main.rs" ]] || fail "xous-core at \`${root}\` (${label}) is not an xous-core root (missing xtask)."
  [[ -f "$root/services/usb-bao1x/Cargo.toml" ]] || fail "xous-core at \`${root}\` (${label}) is missing services/usb-bao1x."

  if ! grep -qE '^ccid-openpgp\s*=' "$root/services/usb-bao1x/Cargo.toml" \
    && ! grep -q 'ccid-openpgp' "$root/services/usb-bao1x/Cargo.toml"; then
    fail "xous-core at \`${root}\` does not match branch \`${EXPECTED_BRANCH}\` — missing expected feature \`ccid-openpgp\` in usb-bao1x/Cargo.toml."
  fi

  if ! grep -q 'CcidRxDeferred\s*=\s*640' "$root/services/usb-bao1x/src/api.rs" 2>/dev/null; then
    fail "xous-core at \`${root}\` does not match branch \`${EXPECTED_BRANCH}\` — missing expected symbol \`CcidRxDeferred = 640\`."
  fi

  if ! grep -q 'CcidTx\s*=\s*642' "$root/services/usb-bao1x/src/api.rs" 2>/dev/null; then
    fail "xous-core at \`${root}\` does not match branch \`${EXPECTED_BRANCH}\` — missing expected symbol \`CcidTx = 642\`."
  fi

  if [[ -d "$root/.git" ]] || git -C "$root" rev-parse --git-dir >/dev/null 2>&1; then
    local branch
    branch="$(git -C "$root" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
    local head
    head="$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "  HEAD: $head  branch: $branch"
    if [[ "$branch" != "$EXPECTED_BRANCH" && "$branch" != "HEAD" ]]; then
      warn "$label: branch is '$branch', expected '$EXPECTED_BRANCH'.
  Detached HEAD on a CCID commit is OK if features/opcodes above passed."
    fi
    if [[ "$branch" == "HEAD" ]]; then
      warn "$label: detached HEAD ($head); ensure this commit includes ccid-openpgp."
    fi
  else
    warn "$label: not a git checkout; feature/opcode file checks only"
  fi

  echo "  OK: ccid-openpgp + CcidRxDeferred/CcidTx present"
}

echo "Galdralag xous-core preflight"
echo "  Expected branch: $EXPECTED_BRANCH"
echo "  XOUS_CORE (image builds): $XOUS_CORE"
echo ""

check_tree "XOUS_CORE (sibling / image tree)" "$XOUS_CORE" required

# Path deps in services/galdralag/Cargo.toml still use ../../xous-core (nested).
if [[ -L "$NESTED" ]]; then
  echo "Nested path-dep tree is a symlink: $NESTED -> $(readlink -f "$NESTED" || readlink "$NESTED")"
  check_tree "nested xous-core (path deps)" "$NESTED" required
elif [[ -d "$NESTED" ]]; then
  check_tree "nested xous-core (path deps)" "$NESTED" required
  # If both exist and are distinct directories, fail when HEADs differ.
  if [[ -d "$XOUS_CORE/.git" || -d "$NESTED/.git" ]]; then
    h1="$(git -C "$XOUS_CORE" rev-parse HEAD 2>/dev/null || true)"
    h2="$(git -C "$NESTED" rev-parse HEAD 2>/dev/null || true)"
    if [[ -n "$h1" && -n "$h2" && "$h1" != "$h2" ]]; then
      fail "xous-core at \`${NESTED}\` (nested path deps) HEAD (${h2}) differs from XOUS_CORE (${h1}).
galdralag-service path deps compile against the nested tree; image builds use XOUS_CORE."
    fi
  fi
else
  warn "No nested Galdralag-firmware/xous-core — path deps in Cargo.toml will fail until you add one.
Recommended (from Galdralag-firmware root):
  ln -sfn $(symlink_target) ./xous-core"
fi

echo ""
echo "Preflight passed."
