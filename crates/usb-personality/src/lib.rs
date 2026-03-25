//! USB HS personalities: uninformed hosts see **standard mass storage** only; unlock path requires
//! an informed driver (per Baochip host-visible behavior).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

/// Active high-level USB presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Personality {
    /// Encrypted volume presentation without token protocol advertising.
    MassStorageDecoy,
    /// Vendor or integrator protocol after successful authentication.
    AuthenticatedUnlock,
}

/// Opaque capability reference post-unlock (stub).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnlockCapability(pub u32);

/// Returns sensitive material visible to USB stack for this personality.
///
/// **Security role:** **must** be `None` for [`Personality::MassStorageDecoy`] so an uninformed
/// host learns nothing about internal verifier state or keys.
pub fn usb_exposed_secret_slice(p: Personality) -> Option<&'static [u8]> {
    match p {
        Personality::MassStorageDecoy => None,
        Personality::AuthenticatedUnlock => None,
    }
}

/// Stub: set personality after policy allows (Xous IPC to `usbd`).
pub fn set_personality_stub(_p: Personality, _cap: Option<UnlockCapability>) -> Result<(), galdr_core::GaldrError> {
    Err(galdr_core::GaldrError::NotImplemented)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod property_tests;
