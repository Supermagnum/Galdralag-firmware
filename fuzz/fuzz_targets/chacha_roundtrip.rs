#![no_main]

use galdr_core::fake_hal::FakeTrng;
use libfuzzer_sys::fuzz_target;
use vault::chacha_aead::{chacha_decrypt, chacha_encrypt, ChaChaKey, ChaChaNonce};
use vault::kdf_policy::KeyPurpose;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let mut prk = [0u8; 32];
    let n = data.len().min(32);
    prk[..n].copy_from_slice(&data[..n]);
    let k = match ChaChaKey::derive(&prk, KeyPurpose::RramBlobWrap, b"fuzz") {
        Ok(k) => k,
        Err(_) => return,
    };
    let seed = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let mut trng = FakeTrng::from_seed(seed);
    let nonce = match ChaChaNonce::generate(&mut trng) {
        Ok(n) => n,
        Err(_) => return,
    };
    let ct = match chacha_encrypt(&k, &nonce, &[], data) {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = chacha_decrypt(&k, &nonce, &[], &ct);
});
