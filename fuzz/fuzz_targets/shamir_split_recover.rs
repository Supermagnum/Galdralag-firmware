#![no_main]

use galdr_core::fake_hal::FakeTrng;
use libfuzzer_sys::fuzz_target;
use rand_core::RngCore;
use vault::shamir::{shamir_recover, shamir_split};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let seed = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0u8; 8]));
    let mut trng = FakeTrng::from_seed(seed);
    let len = 16 + (data.get(1).copied().unwrap_or(0) as usize % 49);
    if len > 64 {
        return;
    }
    let mut secret = [0u8; 64];
    trng.fill_bytes(&mut secret[..len]);
    let n = 2 + (data.get(2).copied().unwrap_or(0) as usize % 5);
    let n = n as u8;
    let k = 1 + (data.get(3).copied().unwrap_or(0) as usize % (n as usize));
    let k = k as u8;
    let shares = match shamir_split(&secret[..len], k, n, &mut trng) {
        Ok(s) => s,
        Err(_) => return,
    };
    let kk = k as usize;
    if kk <= shares.len() {
        let slice = &shares.as_slice()[..kk];
        let _ = shamir_recover(slice, k);
    }
});
