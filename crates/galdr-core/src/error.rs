//! Shared error types for cross-service IPC, HAL, and high-level vault operations.

/// Outcomes for operations that cross crate boundaries (IPC, policy, crypto helpers).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GaldrError {
    /// Feature or code path not implemented yet (scaffold until wired to services such as Xous).
    NotImplemented,
    /// Privileged IPC or service path is unavailable in this build (stub handler).
    ///
    /// Callers **must** treat this as a permanent denial for the current firmware image — not as a
    /// transient fault, not as "retry later", and not as ignorable. Real implementations replace
    /// the stub with policy-checked handlers; until then, privileged operations stay blocked.
    PrivilegedOperationDenied,
    /// Caller lacked capability or policy denied the operation.
    Denied,
    /// Integrity or authentication check failed.
    Integrity,
    /// Device has zeroised; further PIN or unlock attempts are rejected.
    DeviceZeroised,
    /// Key derivation failed: HKDF-Expand rejected the requested output length or PRF setup failed.
    KeyDerivation,
}

impl GaldrError {
    /// Returns `true` when the error means the operation must not be retried as if pending work.
    pub fn is_permanent_denial(self) -> bool {
        matches!(
            self,
            Self::PrivilegedOperationDenied | Self::Denied | Self::DeviceZeroised
        )
    }
}

/// Hardware or bus-level failures below IPC policy errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HalError {
    /// Bus fault or transfer error.
    Bus,
    /// Uncorrectable ECC or similar memory integrity failure.
    EccUncorrectable,
    /// Operation timed out.
    Timeout,
    /// Driver or secure element denied the request.
    Denied,
    /// PIN provision records are missing: operator must run USB CDC provisioning (or a documented
    /// development-only path such as `dev-provisioning` / `trng-pin-fallback`).
    NeedsProvisioning,
}
