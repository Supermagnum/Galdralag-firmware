# Galdralag Xous CCID daemon (`galdralag-service`)

This crate runs as a **separate Xous process**. It connects to **`usb-bao1x`**
(`_Xous USB device driver_`) via **`CcidRxDeferred` / `CcidTx`**, dispatches OpenPGP
APDUs with **`usb_personality`** + **`baochip-openpgp`**, and optionally bridges PIN
material from PDDB into RRAM.

IPC types are duplicated in `src/usb_bao_ipc.rs` so this crate does **not** link
`usb-bao1x` (avoids `pddb` feature unification / `svd2utra` clashes in mixed graphs).

## Required xous-core tree

Path dependencies in this manifest (`bao1x-hal`, `pddb`, `trng`, `svd2utra`) resolve
through **`Galdralag-firmware/xous-core/`** (relative `../../xous-core/...`).

**Image builds** should use a **sibling** checkout (or `XOUS_CORE=...`) of branch
**`feature/usb-bao1x-ccid-openpgp`**
([PR #937](https://github.com/betrusted-io/xous-core/pull/937)).

Do **not** assume the nested tree matches the sibling. Preflight fails non-zero if
`./xous-core` is a stale checkout (missing `CcidRxDeferred = 640`, wrong branch, or
HEAD mismatch) and prints a copy-pasteable fix, for example:

```
ERROR: xous-core at `/…/Galdralag-firmware/xous-core` does not match branch `feature/usb-bao1x-ccid-openpgp` — missing expected symbol `CcidRxDeferred = 640`.

Fix (copy-paste from the Galdralag-firmware repository root):
  mv ./xous-core ./xous-core.stale-nested
  ln -sfn /path/to/sibling-xous-core ./xous-core
```

Recommended lab layout (sibling already on `feature/usb-bao1x-ccid-openpgp`):

```bash
# From Galdralag-firmware root — nested path deps == CCID branch
ln -sfn ../xous-core ./xous-core
cargo run -p xtask -- check-xous-core
```

Preflight (read-only; never edits xous-core):

```bash
cargo run -p xtask -- check-xous-core
# or: scripts/check_xous_core_preflight.sh
```

Anything that requires changing xous-core itself is listed in
[docs/XOUS_CORE_UPSTREAM_REQUESTS.md](../../docs/XOUS_CORE_UPSTREAM_REQUESTS.md).

## Persona A provisioning (current CCID branch)

On **`dabao-ccid`** images there is **no USB CDC provisioning serial** and **no PDDB
service** (Dabao has no SPI flash). Galdralag therefore:

1. Connects to USB early and serves CCID (bring-up stub and/or vault).
2. Waits briefly for PDDB `usb.ccid` / `OKV1` + PIN lines **when PDDB exists** (baosec).
3. On Dabao timeout without OKV1: uses lab defaults **User `12345` / Admin `12345678`**.

**Legacy (baosec + CDC era):** two-line CDC + PDDB `OKV1` via `galdralag-provision` —
documented as **legacy / non-Dabao-CCID** in the root README. Feature **`ccid-pddb`** on
baosec images can still seed PDDB offline.

**Development shortcut:** `dev-provisioning` + env `CCID_USER_PIN` / `CCID_ADMIN_PIN`
(see `baochip-openpgp`). `trng-pin-fallback` is compile-error with `board-dabao`.

## Workspace note

`services/galdralag` is in the root workspace **`exclude`** list. Build via xtask or
manifest path:

```bash
cargo run -p xtask -- build-galdralag-xous release --board dabao
# or baosec:
cargo run -p xtask -- build-galdralag-xous release --board baosec
```

## Including the daemon in a flashable image (no xous-core edits)

### Dabao + CCID + Galdralag (recommended for eval)

Plain **`cargo xtask dabao-ccid`** is **transport-only** (inline ATR / GetSlotStatus).
It will **not** reach `gpg --card-status` APDUs until **`galdralag-service`** is passed
as a positional cratespec (registered as a Flash **service** on current `dabao-ccid`).

One-shot helper (Galdralag side only):

```bash
# Default XOUS_CORE = sibling ../xous-core
scripts/build_dabao_ccid_image.sh
# or:
XOUS_CORE=/path/to/feature-usb-bao1x-ccid-openpgp scripts/build_dabao_ccid_image.sh --no-verify
```

Manual equivalent:

```bash
cargo run -p xtask -- check-xous-core
cargo run -p xtask -- build-galdralag-xous release --board dabao
SPEC=$(cargo run -p xtask --quiet -- print-galdralag-xous-cratespec release)
cd "$XOUS_CORE" && cargo xtask dabao-ccid "$SPEC" --no-verify
```

### BaoSec + CCID (PDDB available)

```bash
cargo run -p xtask -- build-and-register release --xous-core /path/to/xous-core
# Prefer image verb baosec-ccid when invoking xtask yourself:
#   cargo xtask baosec-ccid galdralag-service:/abs/path/to/galdralag-service
```

Also: `scripts/build_dabao_image.sh` historically builds **`baosec-ccid`** + cratespec
(PDDB path; not a pure Dabao recipe).

**Loader** supplies **`PUBLIC_SERIAL`**. Server name matches `usb-bao1x` `api.rs`:
**`_Xous USB device driver_`**.

See [docs/HARDWARE_BRINGUP_TEST_PLAN.md](../../docs/HARDWARE_BRINGUP_TEST_PLAN.md),
[docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) (CCID ownership), and
[docs/RRAM_LAYOUT.md](../../docs/RRAM_LAYOUT.md).
