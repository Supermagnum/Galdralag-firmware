//! Vault IPC surface (Xous messages to be wired). Stubs return [`GaldrError::NotImplemented`].

use crate::GaldrError;

/// High-level vault operations invoked by other servers (PIN policy, USB personality, boot).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VaultRequest {
    /// Seal plaintext into an RRAM slot (AEAD parameters TBD).
    Seal { slot: u32 },
    /// Unseal a slot into a scoped buffer handle (Xous memory server).
    Unseal { slot: u32 },
    /// Trigger full vault zeroisation (ties to boot0 path on Baochip-1x).
    ZeroiseAll { reason_code: u32 },
}

/// Stub vault server; production replaces with `vaultd` over Xous IPC.
pub struct VaultService;

impl Default for VaultService {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultService {
    pub fn new() -> Self {
        Self
    }

    pub fn dispatch(_req: VaultRequest) -> Result<(), GaldrError> {
        Err(GaldrError::NotImplemented)
    }
}
