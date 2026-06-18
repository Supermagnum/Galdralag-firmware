//! CESS Mode A outer ChaCha20-Poly1305 (§6.6, §8.3): `K_outer`, 12-byte nonce, empty AAD.

use alloc::vec::Vec;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use core::fmt;

/// ChaCha20-Poly1305 failure (wrong key, bad tag, truncated wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CessCryptoError {
    AeadEncrypt,
    AeadDecrypt,
    WireTooShort,
}

impl fmt::Display for CessCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CessCryptoError::AeadEncrypt => write!(f, "ChaCha20-Poly1305 encrypt failed"),
            CessCryptoError::AeadDecrypt => write!(f, "ChaCha20-Poly1305 decrypt failed"),
            CessCryptoError::WireTooShort => write!(f, "wire shorter than nonce + tag"),
        }
    }
}

/// Seal **outer** plaintext (`suite_id || inner_blob`) with ChaCha20-Poly1305.
///
/// Returns **`nonce` (12) || ciphertext || Poly1305 tag** (RFC 8439 data model).
/// **AAD** is empty (CESS §6.6 default).
pub fn seal_mode_a_outer(
    k_outer: &[u8; 32],
    nonce: &[u8; 12],
    outer_plaintext: &[u8],
) -> Result<Vec<u8>, CessCryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(k_outer));
    let n = Nonce::from_slice(nonce);
    let ct = cipher
        .encrypt(n, outer_plaintext)
        .map_err(|_| CessCryptoError::AeadEncrypt)?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open **Mode A** wire: first 12 octets are `nonce`; remainder is ciphertext || tag.
pub fn open_mode_a_outer(k_outer: &[u8; 32], wire: &[u8]) -> Result<Vec<u8>, CessCryptoError> {
    if wire.len() < 12 + 16 {
        return Err(CessCryptoError::WireTooShort);
    }
    let nonce = Nonce::from_slice(&wire[..12]);
    let ct = &wire[12..];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(k_outer));
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| CessCryptoError::AeadDecrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assemble_mode_a_outer_plaintext;

    #[test]
    fn chacha_roundtrip() {
        let k_outer = [7u8; 32];
        let nonce = [3u8; 12];
        let plain = assemble_mode_a_outer_plaintext(0xE001, b"inner-cipher-blob").unwrap();
        let wire = seal_mode_a_outer(&k_outer, &nonce, &plain).unwrap();
        let back = open_mode_a_outer(&k_outer, &wire).unwrap();
        assert_eq!(back, plain);
    }
}
