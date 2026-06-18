//! On-chip RRAM contact directory for Baochip-1x (54 slots, string heap, AORAM index).
//!
//! Sibling of [`galdr_vault`]; uses vault HKDF labels and `pin-policy` for PIN-gated keys.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

mod crc;
mod error;
mod heap;
mod index;
mod key_region;
mod layout;
mod record;
mod store;
mod timing_log;

pub use error::ContactStoreError;
pub use layout::{
    CONTACT_RECORD_BYTES, CONTACT_SLOT_COUNT, CONTACT_STORE_BASE, CONTACT_STORE_END,
    CONTACT_STORE_INTEGRITY_OFFSET, CONTACT_STORE_PROVISION_COUNTER,
    CONTACT_STORE_PROVISION_MARKER_OFFSET, MAX_PUBLIC_KEY_BYTES, RECIPIENT_SLOT_COUNT,
};
pub use record::{
    field, field_source_get, field_source_set, ContactFlags, ContactRecord, FieldSource, KeyAlgo,
    PinBuffer, PublicKeyBlob, StringRef,
};
pub use store::{ContactListIter, ContactStore, ContactUpdate, NewContact, SlotIndex};
pub use heap::StringHeap;
pub use index::{ContactIndex, IndexEntry};
pub use key_region::KeyMaterialRegion;
pub use timing_log::{TimingLog, TimingLogEntry};
