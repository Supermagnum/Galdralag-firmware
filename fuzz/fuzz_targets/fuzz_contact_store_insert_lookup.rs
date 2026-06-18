//! Invariant: insert then fingerprint lookup never returns success for a mismatched fingerprint
//! (CS-7 index prefix must be confirmed against the full 32-byte RRAM fingerprint).

#![no_main]

use contact_store::{ContactStore, KeyAlgo, NewContact};
use galdr_core::fake_hal::FakeMonotonicCounter;
use galdr_core::fake_hal::FakeVaultStorage;
use contact_store::layout::CONTACT_STORE_END;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 40 {
        return;
    }
    let vault = FakeVaultStorage::new(CONTACT_STORE_END as usize + 4096);
    let mut store = ContactStore::new(vault, FakeMonotonicCounter::new(0), [0x11u8; 32]);
    let mut prov = FakeMonotonicCounter::new(0);
    if store.provision_fresh(&mut prov).is_err() || store.init_on_boot().is_err() {
        return;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&data[..32]);
    let email_len = (data[32] as usize % 32) + 1;
    if 33 + email_len > data.len() {
        return;
    }
    let email = &data[33..33 + email_len];
    let n = NewContact {
        fingerprint: fp,
        callsign: [0u8; 12],
        dmr_id: 0,
        key_algo: KeyAlgo::Ed25519,
        public_key: &data[..32.min(data.len())],
        email,
        display_name: None,
        own_identity: false,
        pin_protected: false,
        pin_verifier: None,
        pin_nonce: None,
        pin_tag: None,
    };
    if store.insert(n).is_err() {
        return;
    }
    let mut wrong = fp;
    wrong[31] ^= 0xff;
    if store.lookup_by_fingerprint(&wrong).is_ok() {
        panic!("prefix collision without full fp match");
    }
});
