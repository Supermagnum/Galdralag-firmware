// Cryptographic correctness of each cipher layer is verified by the
// Wycheproof test suites in vault/tests/. This module composes those
// implementations; it does not re-implement any primitive.

//! Multi-layer encrypt and decrypt.
//!
//! Built-in profiles whose names map to a CESS registry [`suite_id`](cess::suite_id_for_profile_name)
//! use **HKDF-BLAKE3** with UTF-8 `info` strings per **CESS v0.2 §8.3** (and distinct per-layer
//! suffixes for cascade subkeys). Custom profiles without a registry mapping continue to use
//! **HKDF-SHA256** over a **32-byte** PRK and [`layer_key_info`](crate::domain::layer_key_info) labels.

extern crate alloc;

use crate::domain::{layer_key_info, layer_nonce_info, MAX_CASCADE_PLAINTEXT};
use crate::error::CipherProfileError;
use crate::layer::CipherLayer;
use crate::profile::CipherProfile;
use aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use cess::{
    hkdf_blake3, suite_id_for_profile_name, CessInnerEtM64Cipher, cess_inner_cascade_etm64_info,
    cess_inner_cascade_layer_key_info, cess_inner_cascade_layer_nonce_info,
};
use heapless::Vec;
use vault::chacha_aead::{
    chacha_decrypt, chacha_encrypt, ChaChaCiphertext, ChaChaKey, ChaChaNonce, ChaChaPlaintext,
};
use vault::serpent_cipher::{
    serpent_decrypt, serpent_encrypt, SerpentCiphertext, SerpentKey, SerpentNonce, SerpentPlaintext,
};
use vault::twofish_cipher::{
    twofish_decrypt, twofish_encrypt, TwofishCiphertext, TwofishKey, TwofishNonce, TwofishPlaintext,
};
use zeroize::Zeroize;

const MAX_CT: usize = 65536;

/// Authenticated cascade output (outer ciphertext only).
#[derive(Debug)]
pub struct CascadeCiphertext {
    /// Profile name used for encryption.
    pub profile_name: heapless::String<64>,
    /// Ciphertext bytes from the outermost layer.
    pub ciphertext: Vec<u8, MAX_CT>,
}

/// Plaintext after successful cascade decrypt (zeroised on drop).
pub struct CascadePlaintext {
    buf: Vec<u8, MAX_CT>,
}

impl Zeroize for CascadePlaintext {
    fn zeroize(&mut self) {
        self.buf.as_mut_slice().zeroize();
    }
}

impl Drop for CascadePlaintext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl CascadePlaintext {
    /// Borrow decrypted plaintext.
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

fn hkdf_blake3_okm32(ikm: &[u8], info: &[u8]) -> Result<[u8; 32], CipherProfileError> {
    let v = hkdf_blake3(ikm, b"", info, 32);
    v.try_into()
        .map_err(|_| CipherProfileError::KeyDerivation)
}

fn hkdf_blake3_okm64(ikm: &[u8], info: &[u8]) -> Result<[u8; 64], CipherProfileError> {
    let v = hkdf_blake3(ikm, b"", info, 64);
    v.try_into()
        .map_err(|_| CipherProfileError::KeyDerivation)
}

/// Encrypt `plaintext` with the profile cascade (inner layers first).
///
/// `ikm` is key material for layer derivation:
/// - **CESS path** (built-in profile name maps to a listed `suite_id`): **classical ECDH shared
///   secret** octets (the same IKM fed to [`cess::derive_k_outer`]), per CESS §8.3.
/// - **Legacy path** (no `suite_id` mapping): a **32-byte** HKDF-SHA256 PRK (e.g. HKDF-Extract output
///   used only for custom profiles).
/// - **Real sessions (CESS-mapped profiles):** pass [`ephemeral_session::SessionKeys::cess_inner_cascade_ikm`]
///   (raw classical ECDH octets, same source as `K_outer` IKM per CESS §8.3), not
///   [`ephemeral_session::SessionKeys::profile_prk`].
pub fn cascade_encrypt(
    profile: &CipherProfile,
    ikm: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<CascadeCiphertext, CipherProfileError> {
    if plaintext.len() > MAX_CASCADE_PLAINTEXT {
        return Err(CipherProfileError::PayloadTooLarge);
    }
    let cess_sid = suite_id_for_profile_name(profile.name());
    if cess_sid.is_none() && ikm.len() != 32 {
        return Err(CipherProfileError::KeyDerivation);
    }
    let name = profile.name();
    let layers = profile.layers();
    let n = layers.len();
    let mut current = Vec::<u8, MAX_CT>::new();
    for b in plaintext {
        current.push(*b).map_err(|_| CipherProfileError::PayloadTooLarge)?;
    }
    for (i, layer) in layers.iter().enumerate() {
        let layer_aad = if i + 1 == n { aad } else { &[][..] };
        let kinfo = layer_key_info(name, *layer, i as u8)?;
        let ninfo = layer_nonce_info(name, *layer, i as u8)?;
        current = encrypt_layer(
            ikm,
            cess_sid,
            *layer,
            layer_aad,
            current.as_slice(),
            kinfo.as_slice(),
            ninfo.as_slice(),
            i as u8,
        )?;
    }
    let mut pname = heapless::String::new();
    pname
        .push_str(name)
        .map_err(|_| CipherProfileError::InvalidProfileName)?;
    Ok(CascadeCiphertext {
        profile_name: pname,
        ciphertext: current,
    })
}

/// Decrypt a cascade ciphertext (outer layer first). All failures map to [`CipherProfileError::AuthenticationFailed`].
pub fn cascade_decrypt(
    profile: &CipherProfile,
    ikm: &[u8],
    aad: &[u8],
    ct: &CascadeCiphertext,
) -> Result<CascadePlaintext, CipherProfileError> {
    if ct.profile_name.as_str() != profile.name() {
        return Err(CipherProfileError::ProfileMismatch);
    }
    let cess_sid = suite_id_for_profile_name(profile.name());
    if cess_sid.is_none() && ikm.len() != 32 {
        return Err(CipherProfileError::AuthenticationFailed);
    }
    let name = profile.name();
    let layers = profile.layers();
    let n = layers.len();
    let mut buf = Vec::<u8, MAX_CT>::new();
    for b in ct.ciphertext.iter() {
        buf.push(*b).map_err(|_| CipherProfileError::AuthenticationFailed)?;
    }
    for idx in (0..n).rev() {
        let layer = layers[idx];
        let layer_aad = if idx + 1 == n { aad } else { &[][..] };
        let kinfo = map_decrypt_err(layer_key_info(name, layer, idx as u8))?;
        let ninfo = map_decrypt_err(layer_nonce_info(name, layer, idx as u8))?;
        buf = decrypt_layer(
            ikm,
            cess_sid,
            layer,
            layer_aad,
            buf.as_slice(),
            kinfo.as_slice(),
            ninfo.as_slice(),
            idx as u8,
        )?;
    }
    Ok(CascadePlaintext { buf })
}

fn map_decrypt_err<T>(r: Result<T, CipherProfileError>) -> Result<T, CipherProfileError> {
    r.map_err(|_| CipherProfileError::AuthenticationFailed)
}

fn legacy_prk32(ikm: &[u8]) -> Result<&[u8; 32], CipherProfileError> {
    <&[u8; 32]>::try_from(ikm).map_err(|_| CipherProfileError::KeyDerivation)
}

fn encrypt_layer(
    ikm: &[u8],
    cess_suite_id: Option<u16>,
    layer: CipherLayer,
    aad: &[u8],
    data: &[u8],
    key_info: &[u8],
    nonce_info: &[u8],
    layer_idx: u8,
) -> Result<Vec<u8, MAX_CT>, CipherProfileError> {
    if let Some(sid) = cess_suite_id {
        return encrypt_layer_cess(ikm, sid, layer, aad, data, layer_idx);
    }
    let prk = legacy_prk32(ikm)?;
    match layer {
        CipherLayer::Aes256Gcm => aes_encrypt(prk, aad, data, key_info, nonce_info),
        CipherLayer::ChaCha20Poly1305 => {
            let key = ChaChaKey::derive_from_prk_label(prk.as_slice(), key_info)
                .map_err(|_| CipherProfileError::KeyDerivation)?;
            let nonce = ChaChaNonce::derive_from_prk_label(prk.as_slice(), nonce_info)
                .map_err(|_| CipherProfileError::KeyDerivation)?;
            let ct = chacha_encrypt(&key, &nonce, aad, data)
                .map_err(|e| map_cipher_encrypt_err(e, layer_idx))?;
            copy_ct_chacha(&ct)
        }
        CipherLayer::Twofish256 => {
            let key = TwofishKey::derive_from_prk_label(prk.as_slice(), key_info)
                .map_err(|_| CipherProfileError::KeyDerivation)?;
            let nonce = TwofishNonce::derive_from_prk_label(prk.as_slice(), nonce_info)
                .map_err(|_| CipherProfileError::KeyDerivation)?;
            let ct = twofish_encrypt(&key, &nonce, aad, data)
                .map_err(|e| map_twofish_encrypt_err(e, layer_idx))?;
            copy_ct_twofish(&ct)
        }
        CipherLayer::Serpent256 => {
            let key = SerpentKey::derive_from_prk_label(prk.as_slice(), key_info)
                .map_err(|_| CipherProfileError::KeyDerivation)?;
            let nonce = SerpentNonce::derive_from_prk_label(prk.as_slice(), nonce_info)
                .map_err(|_| CipherProfileError::KeyDerivation)?;
            let ct = serpent_encrypt(&key, &nonce, aad, data)
                .map_err(|e| map_serpent_encrypt_err(e, layer_idx))?;
            copy_ct_serpent(&ct)
        }
    }
}

fn encrypt_layer_cess(
    ikm: &[u8],
    sid: u16,
    layer: CipherLayer,
    aad: &[u8],
    data: &[u8],
    layer_idx: u8,
) -> Result<Vec<u8, MAX_CT>, CipherProfileError> {
    match layer {
        CipherLayer::Aes256Gcm => {
            let ik = cess_inner_cascade_layer_key_info(sid, layer_idx);
            let ink = cess_inner_cascade_layer_nonce_info(sid, layer_idx);
            let key = hkdf_blake3_okm32(ikm, ik.as_slice())?;
            let nb = hkdf_blake3(ikm, b"", ink.as_slice(), 12);
            let nb12: [u8; 12] = nb.try_into().map_err(|_| CipherProfileError::KeyDerivation)?;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
            let nonce = Nonce::from_slice(&nb12);
            let ct = cipher
                .encrypt(nonce, Payload { msg: data, aad })
                .map_err(|_| CipherProfileError::CipherError { layer: layer_idx })?;
            let mut out = Vec::new();
            for b in ct {
                out.push(b).map_err(|_| CipherProfileError::PayloadTooLarge)?;
            }
            Ok(out)
        }
        CipherLayer::ChaCha20Poly1305 => {
            let ik = cess_inner_cascade_layer_key_info(sid, layer_idx);
            let ink = cess_inner_cascade_layer_nonce_info(sid, layer_idx);
            let key_b = hkdf_blake3_okm32(ikm, ik.as_slice())?;
            let n_b = hkdf_blake3_okm32(ikm, ink.as_slice())?;
            let key = ChaChaKey::from_symmetric_key_material(key_b);
            let nonce = ChaChaNonce::from_okm32_prefix(&n_b);
            let ct = chacha_encrypt(&key, &nonce, aad, data)
                .map_err(|e| map_cipher_encrypt_err(e, layer_idx))?;
            copy_ct_chacha(&ct)
        }
        CipherLayer::Twofish256 => {
            let inf = cess_inner_cascade_etm64_info(sid, layer_idx, CessInnerEtM64Cipher::Twofish256);
            let okm = hkdf_blake3_okm64(ikm, inf.as_slice())?;
            let key = TwofishKey::from_okm64(&okm);
            let n_inf = cess_inner_cascade_layer_nonce_info(sid, layer_idx);
            let n_okm = hkdf_blake3_okm32(ikm, n_inf.as_slice())?;
            let nonce = TwofishNonce::from_okm32_prefix(&n_okm);
            let ct = twofish_encrypt(&key, &nonce, aad, data)
                .map_err(|e| map_twofish_encrypt_err(e, layer_idx))?;
            copy_ct_twofish(&ct)
        }
        CipherLayer::Serpent256 => {
            let inf = cess_inner_cascade_etm64_info(sid, layer_idx, CessInnerEtM64Cipher::Serpent256);
            let okm = hkdf_blake3_okm64(ikm, inf.as_slice())?;
            let key = SerpentKey::from_okm64(&okm);
            let n_inf = cess_inner_cascade_layer_nonce_info(sid, layer_idx);
            let n_okm = hkdf_blake3_okm32(ikm, n_inf.as_slice())?;
            let nonce = SerpentNonce::from_okm32_prefix(&n_okm);
            let ct = serpent_encrypt(&key, &nonce, aad, data)
                .map_err(|e| map_serpent_encrypt_err(e, layer_idx))?;
            copy_ct_serpent(&ct)
        }
    }
}

fn decrypt_layer(
    ikm: &[u8],
    cess_suite_id: Option<u16>,
    layer: CipherLayer,
    aad: &[u8],
    data: &[u8],
    key_info: &[u8],
    nonce_info: &[u8],
    layer_idx: u8,
) -> Result<Vec<u8, MAX_CT>, CipherProfileError> {
    if let Some(sid) = cess_suite_id {
        return decrypt_layer_cess(ikm, sid, layer, aad, data, layer_idx);
    }
    let prk = legacy_prk32(ikm).map_err(|_| CipherProfileError::AuthenticationFailed)?;
    match layer {
        CipherLayer::Aes256Gcm => aes_decrypt(prk, aad, data, key_info, nonce_info),
        CipherLayer::ChaCha20Poly1305 => {
            let key = ChaChaKey::derive_from_prk_label(prk.as_slice(), key_info)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let nonce = ChaChaNonce::derive_from_prk_label(prk.as_slice(), nonce_info)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let ct = ChaChaCiphertext::try_from_slice(data)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let pt = chacha_decrypt(&key, &nonce, aad, &ct).map_err(|_| {
                let _ = layer_idx;
                CipherProfileError::AuthenticationFailed
            })?;
            copy_pt_chacha(&pt)
        }
        CipherLayer::Twofish256 => {
            let key = TwofishKey::derive_from_prk_label(prk.as_slice(), key_info)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let nonce = TwofishNonce::derive_from_prk_label(prk.as_slice(), nonce_info)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let ct = TwofishCiphertext::from_bytes_fuzz(data)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let pt = twofish_decrypt(&key, &nonce, aad, &ct)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            copy_pt_twofish(&pt)
        }
        CipherLayer::Serpent256 => {
            let key = SerpentKey::derive_from_prk_label(prk.as_slice(), key_info)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let nonce = SerpentNonce::derive_from_prk_label(prk.as_slice(), nonce_info)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let ct = SerpentCiphertext::from_bytes_fuzz(data)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let pt = serpent_decrypt(&key, &nonce, aad, &ct)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            copy_pt_serpent(&pt)
        }
    }
}

fn decrypt_layer_cess(
    ikm: &[u8],
    sid: u16,
    layer: CipherLayer,
    aad: &[u8],
    data: &[u8],
    layer_idx: u8,
) -> Result<Vec<u8, MAX_CT>, CipherProfileError> {
    match layer {
        CipherLayer::Aes256Gcm => {
            let ik = cess_inner_cascade_layer_key_info(sid, layer_idx);
            let ink = cess_inner_cascade_layer_nonce_info(sid, layer_idx);
            let key = hkdf_blake3_okm32(ikm, ik.as_slice())
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let nb = hkdf_blake3(ikm, b"", ink.as_slice(), 12);
            let nb12: [u8; 12] = nb
                .try_into()
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
            let nonce = Nonce::from_slice(&nb12);
            let pt = cipher
                .decrypt(nonce, Payload { msg: data, aad })
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let mut out = Vec::new();
            for b in pt {
                out.push(b).map_err(|_| CipherProfileError::AuthenticationFailed)?;
            }
            Ok(out)
        }
        CipherLayer::ChaCha20Poly1305 => {
            let ik = cess_inner_cascade_layer_key_info(sid, layer_idx);
            let ink = cess_inner_cascade_layer_nonce_info(sid, layer_idx);
            let key_b = hkdf_blake3_okm32(ikm, ik.as_slice())
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let n_b = hkdf_blake3_okm32(ikm, ink.as_slice())
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let key = ChaChaKey::from_symmetric_key_material(key_b);
            let nonce = ChaChaNonce::from_okm32_prefix(&n_b);
            let ct = ChaChaCiphertext::try_from_slice(data)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let pt = chacha_decrypt(&key, &nonce, aad, &ct)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            copy_pt_chacha(&pt)
        }
        CipherLayer::Twofish256 => {
            let inf = cess_inner_cascade_etm64_info(sid, layer_idx, CessInnerEtM64Cipher::Twofish256);
            let okm = hkdf_blake3_okm64(ikm, inf.as_slice())
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let key = TwofishKey::from_okm64(&okm);
            let n_inf = cess_inner_cascade_layer_nonce_info(sid, layer_idx);
            let n_okm = hkdf_blake3_okm32(ikm, n_inf.as_slice())
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let nonce = TwofishNonce::from_okm32_prefix(&n_okm);
            let ct = TwofishCiphertext::from_bytes_fuzz(data)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let pt = twofish_decrypt(&key, &nonce, aad, &ct)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            copy_pt_twofish(&pt)
        }
        CipherLayer::Serpent256 => {
            let inf = cess_inner_cascade_etm64_info(sid, layer_idx, CessInnerEtM64Cipher::Serpent256);
            let okm = hkdf_blake3_okm64(ikm, inf.as_slice())
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let key = SerpentKey::from_okm64(&okm);
            let n_inf = cess_inner_cascade_layer_nonce_info(sid, layer_idx);
            let n_okm = hkdf_blake3_okm32(ikm, n_inf.as_slice())
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let nonce = SerpentNonce::from_okm32_prefix(&n_okm);
            let ct = SerpentCiphertext::from_bytes_fuzz(data)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            let pt = serpent_decrypt(&key, &nonce, aad, &ct)
                .map_err(|_| CipherProfileError::AuthenticationFailed)?;
            copy_pt_serpent(&pt)
        }
    }
}

fn aes_encrypt(
    prk: &[u8; 32],
    aad: &[u8],
    pt: &[u8],
    key_info: &[u8],
    nonce_info: &[u8],
) -> Result<Vec<u8, MAX_CT>, CipherProfileError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::from_prk(prk.as_slice()).map_err(|_| CipherProfileError::KeyDerivation)?;
    let mut key = [0u8; 32];
    hk.expand(key_info, &mut key)
        .map_err(|_| CipherProfileError::KeyDerivation)?;
    let mut nb = [0u8; 12];
    hk.expand(nonce_info, &mut nb)
        .map_err(|_| CipherProfileError::KeyDerivation)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(&nb);
    let ct = cipher
        .encrypt(nonce, Payload { msg: pt, aad })
        .map_err(|_| CipherProfileError::CipherError { layer: 0 })?;
    let mut out = Vec::new();
    for b in ct {
        out.push(b).map_err(|_| CipherProfileError::PayloadTooLarge)?;
    }
    Ok(out)
}

fn aes_decrypt(
    prk: &[u8; 32],
    aad: &[u8],
    ct: &[u8],
    key_info: &[u8],
    nonce_info: &[u8],
) -> Result<Vec<u8, MAX_CT>, CipherProfileError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk =
        Hkdf::<Sha256>::from_prk(prk.as_slice()).map_err(|_| CipherProfileError::AuthenticationFailed)?;
    let mut key = [0u8; 32];
    hk.expand(key_info, &mut key)
        .map_err(|_| CipherProfileError::AuthenticationFailed)?;
    let mut nb = [0u8; 12];
    hk.expand(nonce_info, &mut nb)
        .map_err(|_| CipherProfileError::AuthenticationFailed)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(&nb);
    let pt = cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| CipherProfileError::AuthenticationFailed)?;
    let mut out = Vec::new();
    for b in pt {
        out.push(b).map_err(|_| CipherProfileError::AuthenticationFailed)?;
    }
    Ok(out)
}

fn copy_ct_chacha(ct: &ChaChaCiphertext) -> Result<Vec<u8, MAX_CT>, CipherProfileError> {
    let mut out = Vec::new();
    for b in ct.as_slice() {
        out.push(*b).map_err(|_| CipherProfileError::PayloadTooLarge)?;
    }
    Ok(out)
}

fn copy_pt_chacha(pt: &ChaChaPlaintext) -> Result<Vec<u8, MAX_CT>, CipherProfileError> {
    let mut out = Vec::new();
    for b in pt.as_slice() {
        out.push(*b).map_err(|_| CipherProfileError::AuthenticationFailed)?;
    }
    Ok(out)
}

fn copy_ct_twofish(ct: &TwofishCiphertext) -> Result<Vec<u8, MAX_CT>, CipherProfileError> {
    let mut out = Vec::new();
    for b in ct.as_slice() {
        out.push(*b).map_err(|_| CipherProfileError::PayloadTooLarge)?;
    }
    Ok(out)
}

fn copy_pt_twofish(pt: &TwofishPlaintext) -> Result<Vec<u8, MAX_CT>, CipherProfileError> {
    let mut out = Vec::new();
    for b in pt.as_slice() {
        out.push(*b).map_err(|_| CipherProfileError::AuthenticationFailed)?;
    }
    Ok(out)
}

fn copy_ct_serpent(ct: &SerpentCiphertext) -> Result<Vec<u8, MAX_CT>, CipherProfileError> {
    let mut out = Vec::new();
    for b in ct.as_slice() {
        out.push(*b).map_err(|_| CipherProfileError::PayloadTooLarge)?;
    }
    Ok(out)
}

fn copy_pt_serpent(pt: &SerpentPlaintext) -> Result<Vec<u8, MAX_CT>, CipherProfileError> {
    let mut out = Vec::new();
    for b in pt.as_slice() {
        out.push(*b).map_err(|_| CipherProfileError::AuthenticationFailed)?;
    }
    Ok(out)
}

fn map_cipher_encrypt_err(
    e: vault::chacha_aead::ChaChaError,
    layer: u8,
) -> CipherProfileError {
    match e {
        vault::chacha_aead::ChaChaError::AuthenticationFailed => CipherProfileError::CipherError { layer },
        _ => CipherProfileError::CipherError { layer },
    }
}

fn map_twofish_encrypt_err(e: vault::twofish_cipher::TwofishError, layer: u8) -> CipherProfileError {
    match e {
        vault::twofish_cipher::TwofishError::AuthenticationFailed => CipherProfileError::CipherError { layer },
        _ => CipherProfileError::CipherError { layer },
    }
}

fn map_serpent_encrypt_err(e: vault::serpent_cipher::SerpentError, layer: u8) -> CipherProfileError {
    match e {
        vault::serpent_cipher::SerpentError::AuthenticationFailed => CipherProfileError::CipherError { layer },
        _ => CipherProfileError::CipherError { layer },
    }
}
