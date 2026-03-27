//! Error types for cipher profiles and cascades.

/// Errors from profile construction, registry, and cascade operations.
#[derive(Debug, Eq, PartialEq)]
pub enum CipherProfileError {
    /// No cipher layers defined. A profile must have at least one layer.
    NoLayers,

    /// Too many cipher layers. Maximum is 4.
    TooManyLayers,

    /// The same cipher appears more than once in the layer stack.
    DuplicateCipher,

    /// A cipher layer produced an authentication failure (decrypt path; layer not disclosed).
    AuthenticationFailed,

    /// A cipher layer failed for a non-authentication reason (encrypt path only).
    CipherError {
        /// Layer index (0-based).
        layer: u8,
    },

    /// The profile name is empty or contains invalid characters.
    InvalidProfileName,

    /// The profile has been locked (finalised) and cannot be modified.
    ProfileLocked,

    /// A named profile was not found in the registry.
    ProfileNotFound,

    /// The registry already holds the maximum number of profiles.
    RegistryFull,

    /// Ciphertext was produced with a different profile name than the one supplied for decrypt.
    ProfileMismatch,

    /// Serialised profile bytes are truncated or malformed.
    MalformedEncoding,

    /// The Shamir configuration is invalid (k=0, k>n, n=255 overflow, etc.).
    InvalidShamirConfig,

    /// HKDF key derivation failed.
    KeyDerivation,

    /// No ECDHE curve was set on the builder, or curve does not match an expectation.
    CurveMismatch,

    /// Plaintext or intermediate buffer exceeds the cascade limit.
    PayloadTooLarge,

    /// Underlying vault error.
    Vault,
}
