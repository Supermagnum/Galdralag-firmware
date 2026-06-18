//! Galdralag USB CCID service entry point (scaffold).
//!
//! Production **Xous** CCID/OpenPGP wiring lives in the **xous-core** tree:
//! **`services/usb-bao1x`** with feature **`ccid-openpgp`**, using **`baochip-openpgp`**
//! from this repository (`crates/baochip-openpgp`). RRAM layout: `docs/RRAM_LAYOUT.md`.
//! README: **Known limitations / open work** (CCID initial PIN UX).

fn main() {
    // Reference implementation: xous-core/services/usb-bao1x (OpenPgpVaultBackend,
    // OpenPgpCcidDispatcher, CcidClass, RRAM map, provisioning).
    todo!("this crate is not the deployed USB server — use usb-bao1x in xous-core; see module rustdoc")
}
