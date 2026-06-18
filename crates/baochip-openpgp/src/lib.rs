//! OpenPGP vault and CCID types for **Baochip-1x under Xous**.
//!
//! On non-Xous targets this crate is intentionally empty so the Galdralag workspace can be checked
//! on a host triple. Production wiring uses RRAM via [`bao1x_hal::rram::Reram`], [`trng::Trng`],
//! and [`usb_personality`].

#[cfg(all(feature = "trng-pin-fallback", feature = "board-dabao"))]
compile_error!(
    "trng-pin-fallback is not allowed with board-dabao: production images must use USB CDC provisioning \
     (or dev-provisioning for lab builds only)."
);

#[cfg(target_os = "xous")]
mod xous_impl;

#[cfg(target_os = "xous")]
pub use xous_impl::{
    ccid_pin_hashes_unprovisioned, init_pin_zeroise_singleton, load_or_derive_ccid_master_key,
    load_or_provision_ccid_admin_pin_bytes, load_or_provision_ccid_user_pin_bytes,
    map_openpgp_rram_windows, master_key_from_hex64, open_or_provision_backend, openpgp_vault_logical_span_end,
    provision_slots_have_valid_pins, write_provisioning_pins, BaochipPinZeroise, BaochipVaultBackend,
    BaochipVaultZeroise, RramMonotonicCounter, RramVaultStorage, CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES,
    CCID_PIN_PROVISION_SLOT_BYTES, OPENPGP_MASTER_RECORD_BYTES,
};

#[cfg(all(target_os = "xous", feature = "dev-provisioning"))]
pub use xous_impl::{ccid_pins_dev_from_env, master_key_dev_from_env};
