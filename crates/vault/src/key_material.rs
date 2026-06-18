//! Key material newtypes: **`Copy` and `Clone` are intentionally absent** (see unit tests).
//!
//! **Security role:** limits accidental duplication of secrets; combine with `zeroize` on drop for
//! RAM-backed material. RRAM ciphertext still requires AEAD from audited crates (not implemented
//! in this scaffold).

use zeroize::{Zeroize, ZeroizeOnDrop};

/// 256-bit vault secret (e.g. AES-256 key). **Do not add `Copy`/`Clone`.**
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey256([u8; 32]);

impl VaultKey256 {
    pub const fn new_zeroed() -> Self {
        Self([0u8; 32])
    }

    pub fn as_mut_array(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

/// Placeholder for ephemeral X25519 / ECDH material before HKDF install (real code uses `x25519-dalek`).
///
/// **Security role:** must be dropped immediately after session key derivation (see `session` tests).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralEcdhSecretMaterial([u8; 32]);

impl EphemeralEcdhSecretMaterial {
    pub const fn new_zeroed() -> Self {
        Self([0u8; 32])
    }
}
