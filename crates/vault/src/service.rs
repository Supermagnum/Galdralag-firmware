//! Vault IPC surface (Xous messages to be wired). Stubs fail closed with
//! [`GaldrError::PrivilegedOperationDenied`].

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

    /// Dispatch a privileged vault IPC request.
    ///
    /// **Fail-closed contract:** until `vaultd` exists, every variant returns
    /// [`GaldrError::PrivilegedOperationDenied`]. Callers must propagate that error and must not
    /// treat it as [`GaldrError::NotImplemented`] (retry-later semantics).
    pub fn dispatch(req: VaultRequest) -> Result<(), GaldrError> {
        match req {
            VaultRequest::Seal { .. } | VaultRequest::Unseal { .. } | VaultRequest::ZeroiseAll { .. } => {
                Err(GaldrError::PrivilegedOperationDenied)
            }
        }
    }
}

#[cfg(test)]
mod fail_closed_tests {
    use super::*;

    #[test]
    fn seal_stub_is_fail_closed() {
        let err = VaultService::dispatch(VaultRequest::Seal { slot: 0 });
        assert_eq!(err, Err(GaldrError::PrivilegedOperationDenied));
        assert!(err.unwrap_err().is_permanent_denial());
    }

    #[test]
    fn unseal_stub_is_fail_closed() {
        let err = VaultService::dispatch(VaultRequest::Unseal { slot: 1 });
        assert_eq!(err, Err(GaldrError::PrivilegedOperationDenied));
        assert!(err.unwrap_err().is_permanent_denial());
    }

    #[test]
    fn zeroise_all_stub_is_fail_closed() {
        let err = VaultService::dispatch(VaultRequest::ZeroiseAll { reason_code: 0xDEAD });
        assert_eq!(err, Err(GaldrError::PrivilegedOperationDenied));
        assert!(err.unwrap_err().is_permanent_denial());
    }
}
