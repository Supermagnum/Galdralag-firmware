//! Galdralag USB CCID service entry point (scaffold).
//!
//! Production **Xous** CCID/OpenPGP wiring lives in the **xous-core** tree:
//! **`services/usb-bao1x`** with feature **`ccid-openpgp`**, using **`baochip-openpgp`**
//! from this repository (`crates/baochip-openpgp`). RRAM layout: `docs/RRAM_LAYOUT.md`.
//!
//! **First-boot PIN provisioning:** when `open_or_provision_backend` / `load_or_provision_ccid_*_pin_bytes`
//! returns [`galdr_core::HalError::NeedsProvisioning`], `usb-bao1x` should enumerate **`usb_personality::provisioning::ProvisioningClass`**
//! (feature **`provisioning-personality`**), run the USB poll loop until `COMMIT`, call **`baochip_openpgp::write_provisioning_pins`**,
//! then re-open the vault backend and switch to **`CcidClass`**. Host tool: **`galdralag-provision`** (`crates/host-tools`).

fn main() {
    // Reference implementation: xous-core/services/usb-bao1x (OpenPgpVaultBackend,
    // OpenPgpCcidDispatcher, CcidClass, RRAM map, provisioning).
    todo!("this crate is not the deployed USB server — use usb-bao1x in xous-core; see module rustdoc")
}
