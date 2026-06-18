//! HKDF domain separation labels for per-layer keys and nonces.

use crate::error::CipherProfileError;
use crate::layer::CipherLayer;
use heapless::Vec;

/// Maximum plaintext length for one cascade (matches vault symmetric bounds).
pub const MAX_CASCADE_PLAINTEXT: usize = 8192;

/// Build HKDF-SHA256 `info` for a layer encryption key.
pub fn layer_key_info(
    profile_name: &str,
    cipher: CipherLayer,
    layer_index: u8,
) -> Result<Vec<u8, 128>, CipherProfileError> {
    build_layer_info(profile_name, cipher, layer_index, b"/key/v1")
}

/// Build HKDF-SHA256 `info` for a layer nonce.
pub fn layer_nonce_info(
    profile_name: &str,
    cipher: CipherLayer,
    layer_index: u8,
) -> Result<Vec<u8, 128>, CipherProfileError> {
    build_layer_info(profile_name, cipher, layer_index, b"/nonce/v1")
}

fn build_layer_info(
    profile_name: &str,
    cipher: CipherLayer,
    layer_index: u8,
    suffix: &[u8],
) -> Result<Vec<u8, 128>, CipherProfileError> {
    let mut out = Vec::new();
    push_bytes(&mut out, b"galdralag/profile/")?;
    push_bytes(&mut out, profile_name.as_bytes())?;
    push_bytes(&mut out, b"/")?;
    push_bytes(&mut out, cipher.domain_fragment())?;
    push_bytes(&mut out, b"/layer-")?;
    if layer_index < 10 {
        out.push(b'0' + layer_index)
            .map_err(|_| CipherProfileError::KeyDerivation)?;
    } else if layer_index < 100 {
        out.push(b'0' + (layer_index / 10))
            .map_err(|_| CipherProfileError::KeyDerivation)?;
        out.push(b'0' + (layer_index % 10))
            .map_err(|_| CipherProfileError::KeyDerivation)?;
    } else {
        out.push(b'0' + (layer_index / 100))
            .map_err(|_| CipherProfileError::KeyDerivation)?;
        out.push(b'0' + ((layer_index / 10) % 10))
            .map_err(|_| CipherProfileError::KeyDerivation)?;
        out.push(b'0' + (layer_index % 10))
            .map_err(|_| CipherProfileError::KeyDerivation)?;
    }
    push_bytes(&mut out, suffix)?;
    Ok(out)
}

fn push_bytes(buf: &mut Vec<u8, 128>, s: &[u8]) -> Result<(), CipherProfileError> {
    for b in s {
        buf.push(*b)
            .map_err(|_| CipherProfileError::KeyDerivation)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::CipherLayer;

    fn tr<T, E: core::fmt::Debug>(r: Result<T, E>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn domain_labels_differ_by_layer_index() {
        let a = tr(layer_key_info("test", CipherLayer::Serpent256, 0));
        let b = tr(layer_key_info("test", CipherLayer::Serpent256, 1));
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn domain_labels_differ_by_cipher() {
        let a = tr(layer_key_info("test", CipherLayer::Serpent256, 0));
        let b = tr(layer_key_info("test", CipherLayer::ChaCha20Poly1305, 0));
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn domain_labels_differ_by_profile() {
        let a = tr(layer_key_info("profile-a", CipherLayer::Serpent256, 0));
        let b = tr(layer_key_info("profile-b", CipherLayer::Serpent256, 0));
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn domain_key_and_nonce_differ() {
        let k = tr(layer_key_info("test", CipherLayer::Serpent256, 0));
        let n = tr(layer_nonce_info("test", CipherLayer::Serpent256, 0));
        assert_ne!(k.as_slice(), n.as_slice());
    }
}
