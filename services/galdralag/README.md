# Galdralag Xous CCID daemon (`galdralag-service`)

This crate runs as a **separate Xous process**: it waits until PDDB `usb.ccid` contains the `OKV1`
provisioning sentinel and PIN lines (written by **`usb-bao1x`** after CDC two-line provisioning),
bridges those bytes into RRAM via **`baochip_openpgp::write_provisioning_pins`**, opens the vault
with **`open_or_provision_backend`**, then services **`CcidRxDeferred` / `CcidTx`** against
**`_Xous USB device driver_`** using the IPC layout from `xous-core/services/usb-bao1x/src/api.rs`
(types are duplicated in `src/usb_bao_ipc.rs` so this crate does not link `usb-bao1x`, avoiding
`pddb` feature unification with the USB server in mixed Cargo graphs).

## Workspace note

`services/galdralag` is listed in the **root workspace `exclude`** list: resolving **`pddb` + `bao1x-hal`**
from the bundled `xous-core` snapshot alongside the rest of the Galdralag workspace can fail with an
**`svd2utra`** version conflict. Build this binary from its manifest path against a **matching**
xous `Cargo.lock` / `[patch.crates-io]` set, for example:

```bash
cargo build --manifest-path services/galdralag/Cargo.toml \
  --target riscv32imac-unknown-xous-elf \
  --features xous-bsp --release
```

## Including the daemon in a BaoSec / `baosec` image (no `xous-core` edits)

`xous-core` **`xtask`** registers extra processes via **positional cratespecs** after the image verb:
`get_cratespecs()` collects those tokens and **`baosec_common`** appends each with
`builder.add_service(name, LoaderRegion::Swap)` (see `xous-core/xtask/src/main.rs`). A prebuilt ELF is
specified as **`process_name:absolute_path`** (parsed by `CrateSpec::from` in `xtask/src/builder.rs`).

Spawn order in **`baosec`** is: `xous-swapper`, `keystore`, then `xous-ticktimer`, `xous-log`,
`xous-names`, **`usb-bao1x`**, `bao1x-hal-service`, `modals`, **`pddb`**, `bao-video`, then any positional
cratespecs. **`galdralag-service`** therefore starts after USB and PDDB are already running; the daemon
still **retries** `Ticktimer` / `XousNames` if scheduled earlier in a custom layout, **waits on PDDB**
until `usb.ccid` / `OKV1` and PIN lines exist, **opens the vault**, and only then calls
`request_connection_blocking("_Xous USB device driver_")` and enters the **`CcidRxDeferred`** loop.

**Loader** supplies **`PUBLIC_SERIAL`** to user processes (same as `usb-bao1x`); the CCID server name
matches `usb-bao1x/src/api.rs`: **`_Xous USB device driver_`**.

From **Galdralag-firmware** root, one command builds the ELF, checks it exists, and prints the
**`galdralag-service:<absolute_path>`** cratespec (and optionally runs **`cargo xtask baosec`** in your
**xous-core** tree):

```bash
# Build, verify artifact, print cratespec; then print the manual baosec line (positional cratespec first).
cargo run -p xtask -- build-and-register release

# Same, then run the full image build from your xous-core checkout (--extra-flags must be last).
cargo run -p xtask -- build-and-register release --xous-core /path/to/xous-core --extra-flags --feature board-baosec
```

**`debug`** profile: use **`build-and-register debug`** (or **`debug`** as the first token with the same
optional flags).

Lower-level helpers (**`build-galdralag-xous`**, **`print-galdralag-xous-cratespec`**) remain available;
**`build-and-register`** always runs a fresh **`cargo build`** before emitting a cratespec so a stale ELF
is never printed.

In **xous-core** **`xtask`**, positional cratespecs must appear **immediately after** the **`baosec`**
verb (before any **`--feature`** / other flags). Example:

`cargo xtask baosec galdralag-service:/abs/path/to/galdralag-service --feature board-baosec`

Do **not** use **`--service extra...`** for this case: in `xous-core` xtask, `--service` arguments are
processed **before** the image recipe and would prepend the process ahead of `xous-swapper` / `keystore`
(see `main.rs` around `get_flag("--service")`).

See also **`docs/RRAM_LAYOUT.md`** and the root **README** provisioning section (**`galdralag-provision`**).
