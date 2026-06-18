//! HKDF-BLAKE3 (RFC 5869 structure, HMAC-BLAKE3 PRF) matching CESS `scripts/generate_vectors.py`.

use alloc::vec::Vec;

const HMAC_BLOCK: usize = 64;

fn normalize_hmac_key(key: &[u8]) -> [u8; HMAC_BLOCK] {
    let mut out = [0u8; HMAC_BLOCK];
    if key.len() > HMAC_BLOCK {
        let h = blake3::hash(key);
        out[..32].copy_from_slice(h.as_bytes());
    } else {
        out[..key.len()].copy_from_slice(key);
    }
    out
}

/// HMAC-BLAKE3 (same construction as CESS vector generator).
pub fn hmac_blake3(key: &[u8], data: &[u8]) -> [u8; 32] {
    let k = normalize_hmac_key(key);
    let mut ipad = [0u8; HMAC_BLOCK];
    let mut opad = [0u8; HMAC_BLOCK];
    for i in 0..HMAC_BLOCK {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    let mut inner_input = Vec::with_capacity(HMAC_BLOCK + data.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(data);
    let inner = blake3::hash(&inner_input);
    let mut outer_input = Vec::with_capacity(HMAC_BLOCK + 32);
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(inner.as_bytes());
    *blake3::hash(&outer_input).as_bytes()
}

/// HKDF-BLAKE3: empty `salt` uses 32 zero octets for extract (CESS §6.2).
pub fn hkdf_blake3(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let salt = if salt.is_empty() {
        [0u8; 32].as_slice()
    } else {
        salt
    };
    let prk = hmac_blake3(salt, ikm);
    let mut okm = Vec::new();
    let mut t = Vec::new();
    let mut counter = 1u8;
    while okm.len() < length {
        let mut block_input = Vec::with_capacity(t.len() + info.len() + 1);
        block_input.extend_from_slice(&t);
        block_input.extend_from_slice(info);
        block_input.push(counter);
        t = hmac_blake3(&prk, &block_input).to_vec();
        okm.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    okm.truncate(length);
    okm
}

/// Derive **`K_outer`** for CESS Mode A (§6.6): IKM = classical ECDH shared secret (e.g. 48-byte
/// BrainpoolP384r1 **x** coordinate), empty salt, `info` = [`super::CESS_OUTER_ENVELOPE_INFO_UTF8`].
pub fn derive_k_outer(classical_shared_secret_ikm: &[u8]) -> [u8; 32] {
    let v = hkdf_blake3(
        classical_shared_secret_ikm,
        b"",
        crate::CESS_OUTER_ENVELOPE_INFO_UTF8.as_bytes(),
        32,
    );
    v.try_into()
        .expect("hkdf_blake3 with length 32 returns 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors from CESS `vectors/hkdf_blake3.toml` (must match `generate_vectors.py`).
    #[test]
    fn cess_vector_classical_only_32() {
        let ikm = hex::decode("3df646a590007b20e599678926543bad804f03c4cd15d8122813d97b08b657d9").unwrap();
        let okm = hkdf_blake3(&ikm, b"", b"cess-kem-v1", 32);
        assert_eq!(
            hex::encode(&okm),
            "56c614e8527a62ffdf5dcd7e6f11514201a89016f125925019d81f81a9f5225c"
        );
    }

    #[test]
    fn cess_vector_explicit_salt_32_zero() {
        let ikm = hex::decode("3df646a590007b20e599678926543bad804f03c4cd15d8122813d97b08b657d9").unwrap();
        let salt = [0u8; 32];
        let okm = hkdf_blake3(&ikm, &salt, b"cess-kem-v1", 32);
        assert_eq!(
            hex::encode(&okm),
            "56c614e8527a62ffdf5dcd7e6f11514201a89016f125925019d81f81a9f5225c"
        );
    }

    #[test]
    fn cess_vector_pin_wrap() {
        let ikm = hex::decode("face1bf3a3261bb9ac71ce64c1f9719a70f208496b4acd98ad5955c45fdd6dfc").unwrap();
        let okm = hkdf_blake3(&ikm, b"", b"cess-pin-v1", 32);
        assert_eq!(
            hex::encode(&okm),
            "cb3805b81c7be26fe8dcbbb8281b195984e8cd77d9f2f58fa7bd177e93dd4ca5"
        );
    }

    #[test]
    fn cess_vector_64_byte_expand() {
        let ikm = hex::decode("3df646a590007b20e599678926543bad804f03c4cd15d8122813d97b08b657d9").unwrap();
        let okm = hkdf_blake3(&ikm, b"", b"cess-kem-v1", 64);
        assert_eq!(
            hex::encode(&okm),
            "56c614e8527a62ffdf5dcd7e6f11514201a89016f125925019d81f81a9f5225c1dd33ac43d0e19a2f5d7e1fd2735c1d2a468be5ed0c63d4ce7a59f4230d1bf16"
        );
    }
}
