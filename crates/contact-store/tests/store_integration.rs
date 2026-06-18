//! Integration tests with `galdr-core` test-hal fakes.

use contact_store::{
    ContactStore, ContactStoreError, KeyAlgo, NewContact, PinBuffer, SlotIndex,
    CONTACT_STORE_END, CONTACT_STORE_INTEGRITY_OFFSET, CONTACT_STORE_PROVISION_MARKER_OFFSET,
};
use galdr_core::fake_hal::{FakeMonotonicCounter, FakeVaultStorage};
use galdr_core::MonotonicCounter;
use pin_policy::{PinPolicyConfig, PinPolicyMachine, ZeroisationTrigger};

struct TestZeroise;

impl ZeroisationTrigger for TestZeroise {
    fn trigger_zeroisation(&mut self) {}
}

fn master_key() -> [u8; 32] {
    [0x42u8; 32]
}

fn fresh_store() -> ContactStore<FakeVaultStorage, FakeMonotonicCounter> {
    let vault = FakeVaultStorage::new(CONTACT_STORE_END as usize + 4096);
    let counter = FakeMonotonicCounter::new(0);
    let mut store = ContactStore::new(vault, counter, master_key());
    let mut prov_counter = FakeMonotonicCounter::new(0);
    store
        .provision_fresh(&mut prov_counter)
        .expect("provision_fresh");
    store.init_on_boot().expect("init");
    store
}

fn sample_new<'a>(fp: u8, email: &'a [u8]) -> NewContact<'a> {
    let mut fingerprint = [0u8; 32];
    fingerprint[0] = fp;
    NewContact {
        fingerprint,
        callsign: [0u8; 12],
        dmr_id: 0,
        key_algo: KeyAlgo::Ed25519,
        public_key: &[0xAA; 32],
        email,
        display_name: None,
        own_identity: false,
        pin_protected: false,
        pin_verifier: None,
        pin_nonce: None,
        pin_tag: None,
    }
}

#[test]
fn cs1_integrity_gate_blocks_lookup_before_init() {
    let vault = FakeVaultStorage::new(CONTACT_STORE_END as usize);
    let store = ContactStore::new(vault, FakeMonotonicCounter::new(0), master_key());
    let fp = [1u8; 32];
    match store.lookup_by_fingerprint(&fp) {
        Err(ContactStoreError::NotInitialised) => {}
        _ => panic!("expected NotInitialised"),
    }
}

#[test]
fn insert_and_lookup_by_fingerprint() {
    let mut store = fresh_store();
    let slot = store
        .insert(sample_new(7, b"alice@example.com"))
        .expect("insert");
    let mut fp = [0u8; 32];
    fp[0] = 7;
    let rec = store.lookup_by_fingerprint(&fp).expect("lookup");
    assert!(rec.is_active());
    assert_eq!(slot, SlotIndex(4));
}

#[test]
fn lookup_by_email_scans_heap() {
    let mut store = fresh_store();
    store.insert(sample_new(2, b"bob@test.org")).expect("insert");
    let rec = store.lookup_by_email("bob@test.org").expect("email");
    assert_eq!(rec.fingerprint[0], 2);
}

#[test]
fn recipient_slots_full_after_50_inserts() {
    let mut store = fresh_store();
    for i in 0..50u8 {
        let mut email = [0u8; 16];
        email[0] = b'u';
        email[1] = b'0' + i;
        email[2] = b'@';
        email[3] = b'x';
        let mut n = sample_new(i, &email[..4]);
        n.dmr_id = u32::from(i) + 100;
        store.insert(n).expect("insert");
    }
    match store.insert(sample_new(99, b"overflow@x")) {
        Err(ContactStoreError::RecipientSlotsFull) => {}
        _ => panic!("expected RecipientSlotsFull"),
    }
}

#[test]
fn pin_required_for_protected_read() {
    let mut store = fresh_store();
    let mut n = sample_new(5, b"p@in.test");
    n.pin_protected = true;
    n.pin_verifier = Some([0x11u8; 32]);
    let slot = store.insert(n).expect("insert");
    match store.read_public_key(slot) {
        Err(ContactStoreError::PinRequired) => {}
        _ => panic!("expected PinRequired"),
    }
}

#[test]
fn cs2_pin_counter_before_compare() {
    let mut store = fresh_store();
    let verifier = *blake3::hash(b"123456").as_bytes();
    let mut n = sample_new(8, b"pin8@test");
    n.pin_protected = true;
    n.pin_verifier = Some(verifier);
    let slot = store.insert(n).expect("insert");
    let cfg = PinPolicyConfig::default();
    let mut machine = PinPolicyMachine::new(cfg, TestZeroise);
    let pin = PinBuffer::from_utf8(b"wrong").expect("pin");
    let _ = store.unlock_pin_protected(slot, &pin, &mut machine);
    assert_eq!(store.counter_value().expect("read"), 1);
}

#[test]
fn timing_log_sequence_increases_across_append_and_pin_unlock() {
    let mut store = fresh_store();
    let slot = store.insert(sample_new(1, b"seq@test")).expect("insert");
    store.timing_log_append(slot, 100).expect("append1");
    store.timing_log_append(slot, 200).expect("append2");
    let e0 = store.timing_log_read_entry(0).expect("e0");
    let e1 = store.timing_log_read_entry(1).expect("e1");
    assert!(e1.seq > e0.seq);

    let verifier = *blake3::hash(b"123456").as_bytes();
    let mut n = sample_new(9, b"pin-seq@test");
    n.pin_protected = true;
    n.pin_verifier = Some(verifier);
    let pin_slot = store.insert(n).expect("insert");
    let cfg = PinPolicyConfig::default();
    let mut machine = PinPolicyMachine::new(cfg, TestZeroise);
    let pin = PinBuffer::from_utf8(b"wrong").expect("pin");
    let _ = store.unlock_pin_protected(pin_slot, &pin, &mut machine);

    store.timing_log_append(slot, 300).expect("append3");
    let e2 = store.timing_log_read_entry(2).expect("e2");
    assert!(e2.seq > e1.seq);
}

#[test]
fn provision_fresh_succeeds_and_marks_provisioned() {
    let vault = FakeVaultStorage::new(CONTACT_STORE_END as usize + 4096);
    let mut store = ContactStore::new(vault, FakeMonotonicCounter::new(0), master_key());
    let mut prov = FakeMonotonicCounter::new(0);
    store.provision_fresh(&mut prov).expect("provision");
    assert_eq!(prov.read().expect("read"), 1);
    let mut marker = [0u8; 4];
    store
        .read_storage(CONTACT_STORE_PROVISION_MARKER_OFFSET, &mut marker)
        .expect("read marker");
    assert_eq!(u32::from_le_bytes(marker), 1);
}

#[test]
fn provision_fresh_twice_returns_already_provisioned() {
    let vault = FakeVaultStorage::new(CONTACT_STORE_END as usize + 4096);
    let mut store = ContactStore::new(vault, FakeMonotonicCounter::new(0), master_key());
    let mut prov = FakeMonotonicCounter::new(0);
    store.provision_fresh(&mut prov).expect("first");
    match store.provision_fresh(&mut prov) {
        Err(ContactStoreError::AlreadyProvisioned) => {}
        other => panic!("expected AlreadyProvisioned, got {other:?}"),
    }
}

#[test]
fn verify_integrity_not_provisioned_without_marker() {
    let vault = FakeVaultStorage::new(CONTACT_STORE_END as usize + 4096);
    let mut store = ContactStore::new(vault, FakeMonotonicCounter::new(0), master_key());
    match store.verify_integrity() {
        Err(ContactStoreError::NotProvisioned) => {}
        other => panic!("expected NotProvisioned, got {other:?}"),
    }
}

#[test]
fn verify_integrity_ok_after_provision() {
    let mut store = fresh_store();
    store.verify_integrity().expect("ok");
}

#[test]
fn verify_integrity_mismatch_on_tamper() {
    let mut store = fresh_store();
    let mut buf = [0u8; 1];
    store
        .read_storage(CONTACT_STORE_INTEGRITY_OFFSET, &mut buf)
        .expect("read");
    buf[0] ^= 0xFF;
    store
        .write_storage(CONTACT_STORE_INTEGRITY_OFFSET, &buf)
        .expect("write");
    match store.verify_integrity() {
        Err(ContactStoreError::IntegrityMismatch) => {}
        other => panic!("expected IntegrityMismatch, got {other:?}"),
    }
}

#[test]
fn verify_integrity_does_not_reprovision_on_zero_integrity() {
    let vault = FakeVaultStorage::new(CONTACT_STORE_END as usize + 4096);
    let mut store = ContactStore::new(vault, FakeMonotonicCounter::new(0), master_key());
    let mut prov = FakeMonotonicCounter::new(0);
    store.provision_fresh(&mut prov).expect("provision");
    store
        .write_storage(CONTACT_STORE_INTEGRITY_OFFSET, &[0u8; 32])
        .expect("zero integrity");
    match store.verify_integrity() {
        Err(ContactStoreError::IntegrityMismatch) => {}
        other => panic!("expected IntegrityMismatch, got {other:?}"),
    }
    let mut marker = [0u8; 4];
    store
        .read_storage(CONTACT_STORE_PROVISION_MARKER_OFFSET, &mut marker)
        .expect("marker");
    assert_eq!(u32::from_le_bytes(marker), 1);
}
