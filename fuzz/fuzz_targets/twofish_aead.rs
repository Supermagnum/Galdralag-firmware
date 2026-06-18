#![no_main]

// INVARIANT: arbitrary (key, nonce, aad, ciphertext) inputs must never panic.
// twofish_decrypt must return Err for invalid ciphertexts, never panic.
// twofish_ctr_unauthenticated must never panic on any input length.

use galdr_core::fake_hal::FakeTrng;
use libfuzzer_sys::fuzz_target;
use vault::kdf_policy::KeyPurpose;
use vault::twofish_cipher::{
    twofish_ctr_unauthenticated, twofish_decrypt, twofish_encrypt, TwofishCiphertext, TwofishKey,
    TwofishNonce,
};

fuzz_target!(|data: &[u8]| {
    let prk: [u8; 32] = if data.len() >= 32 {
        let mut a = [0u8; 32];
        a.copy_from_slice(&data[..32]);
        a
    } else {
        let mut a = [0u8; 32];
        a[..data.len()].copy_from_slice(data);
        a
    };
    let key = match TwofishKey::derive(&prk, KeyPurpose::TwofishStorage, b"fuzz") {
        Ok(k) => k,
        Err(_) => return,
    };
    let mut seed = [0u8; 8];
    let n = data.len().min(8);
    seed[..n].copy_from_slice(&data[..n]);
    let seed_u = u64::from_le_bytes(seed);
    let mut trng = FakeTrng::from_seed(seed_u);
    let nonce = match TwofishNonce::generate(&mut trng) {
        Ok(n) => n,
        Err(_) => return,
    };
    let aad_len = data.len().min(128);
    let aad = &data[..aad_len];
    let pt_len = data.len().min(256);
    let pt = &data[..pt_len];
    if let Ok(ct) = twofish_encrypt(&key, &nonce, aad, pt) {
        let _ = twofish_decrypt(&key, &nonce, aad, &ct);
    }
    let mut buf = [0u8; 512];
    let m = data.len().min(512);
    buf[..m].copy_from_slice(&data[..m]);
    let _ = twofish_ctr_unauthenticated(&key, &nonce, &mut buf[..m]);
    if let Ok(ct) = TwofishCiphertext::from_bytes_fuzz(data) {
        let _ = twofish_decrypt(&key, &nonce, aad, &ct);
    }
});
