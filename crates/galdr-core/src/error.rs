//! Shared error types for cross-service IPC and HAL operations.

/// Top-level errors returned by stub service APIs until wired to Xous servers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GaldrError {
    /// Placeholder for unimplemented vault, USB, or policy paths.
    NotImplemented,
    /// Caller lacked capability or policy denied the operation.
    Denied,
    /// Integrity or authentication check failed.
    Integrity,
    /// Device has zeroised; further PIN or unlock attempts are rejected.
    DeviceZeroised,
    /// HKDF or similar key derivation failed (for example output length exceeds RFC 5869 limits).
    KeyDerivation,
}

/// Low-level hardware / driver failures (MMIO, ECC, secure element).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HalError {
    Bus,
    EccUncorrectable,
    Timeout,
    Denied,
}
