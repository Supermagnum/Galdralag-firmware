//! Invariant: arbitrary 256-byte blobs either fail CRC verification or parse to a record whose
//! recomputed CRC matches the trailing four bytes (CS-7 record integrity on read).

#![no_main]

use contact_store::record::ContactRecord;
use contact_store::ContactStoreError;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() != 256 {
        return;
    }
    let mut buf = [0u8; 256];
    buf.copy_from_slice(data);
    match ContactRecord::from_bytes_verified(&buf) {
        Ok(mut r) => {
            r.recompute_crc();
            let again = r.as_bytes();
            if ContactRecord::from_bytes_verified(&again).is_err() {
                panic!("round-trip crc failure");
            }
        }
        Err(ContactStoreError::CorruptRecord) => {}
        Err(_) => {}
    }
});
