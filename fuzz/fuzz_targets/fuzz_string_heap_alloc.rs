//! Invariant: string heap allocations stay within the 64 KiB bound and reads never succeed with
//! an undersized buffer (heap offset/length sanity).

#![no_main]

use contact_store::heap::StringHeap;
use galdr_core::fake_hal::FakeVaultStorage;
use contact_store::layout::CONTACT_STORE_END;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let vault = FakeVaultStorage::new(CONTACT_STORE_END as usize);
    let mut heap = StringHeap::new();
    let chunk = &data[..data.len().min(128)];
    let r = StringHeap::alloc(&mut heap, &mut vault, chunk);
    if r.is_ok() {
        let mut buf = [0u8; 256];
        if StringHeap::read(&heap, &vault, r.unwrap(), &mut buf[..chunk.len()]).is_err() {
            panic!("read failed for valid alloc");
        }
        if StringHeap::read(&heap, &vault, r.unwrap(), &mut buf[..chunk.len().saturating_sub(1)])
            .is_ok()
        {
            panic!("read succeeded with short buffer");
        }
    }
});
