//! Typed errors for contact-store operations.

use core::fmt;
use galdr_core::legacy_removed::MSG_KEY_ALGO_P512;

/// Fallible contact-store outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContactStoreError {
    /// Underlying [`galdr_core::hal::VaultStorage`] read failed.
    StorageRead,
    /// Underlying [`galdr_core::hal::VaultStorage`] write failed.
    StorageWrite,
    /// CRC32C mismatch on a contact record.
    CorruptRecord,
    /// CRC32C mismatch on a timing-log entry.
    CorruptLogEntry,
    /// Lookup found no matching record.
    SlotNotFound,
    /// All 50 recipient slots are occupied.
    RecipientSlotsFull,
    /// String heap or key-material region has insufficient space.
    HeapFull,
    /// Key read attempted on a PIN-protected record without unlock.
    PinRequired,
    /// PIN verification failed or policy reported lockout.
    PinFailed,
    /// Always-on backup-register integrity check failed.
    IntegrityMismatch,
    /// Lookup or mutation before successful [`crate::ContactStore::init_on_boot`].
    NotInitialised,
    /// Slot index is out of range.
    InvalidSlot,
    /// Key blob exceeds [`crate::layout::MAX_PUBLIC_KEY_BYTES`].
    KeyTooLarge,
    /// String field exceeds the maximum length for its type.
    StringTooLong,
    /// Unknown `key_algo` byte in a record.
    InvalidAlgo,
    /// Retired BrainpoolP512r1 (`key_algo` wire byte `0x05`).
    RemovedBrainpoolP512,
    /// Monotonic counter operation failed.
    CounterError,
    /// HKDF or AEAD operation failed.
    Crypto,
    /// Record magic or flags are inconsistent.
    InvalidRecord,
    /// Contact store already provisioned (`provision_fresh` called twice).
    AlreadyProvisioned,
    /// Provisioning counter marker is zero (factory-fresh, not provisioned).
    NotProvisioned,
}

impl fmt::Display for ContactStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContactStoreError::StorageRead => write!(f, "contact store read failed"),
            ContactStoreError::StorageWrite => write!(f, "contact store write failed"),
            ContactStoreError::CorruptRecord => write!(f, "contact record CRC mismatch"),
            ContactStoreError::CorruptLogEntry => write!(f, "timing log entry CRC mismatch"),
            ContactStoreError::SlotNotFound => write!(f, "contact slot not found"),
            ContactStoreError::RecipientSlotsFull => write!(f, "recipient slots full"),
            ContactStoreError::HeapFull => write!(f, "string heap or key region full"),
            ContactStoreError::PinRequired => write!(f, "PIN required for protected key"),
            ContactStoreError::PinFailed => write!(f, "PIN verification failed"),
            ContactStoreError::IntegrityMismatch => write!(f, "contact store integrity mismatch"),
            ContactStoreError::NotInitialised => write!(f, "contact store not initialised"),
            ContactStoreError::InvalidSlot => write!(f, "invalid contact slot index"),
            ContactStoreError::KeyTooLarge => write!(f, "public key too large"),
            ContactStoreError::StringTooLong => write!(f, "string field too long"),
            ContactStoreError::InvalidAlgo => write!(f, "unknown key algorithm byte"),
            ContactStoreError::RemovedBrainpoolP512 => write!(f, "{MSG_KEY_ALGO_P512}"),
            ContactStoreError::CounterError => write!(f, "monotonic counter error"),
            ContactStoreError::Crypto => write!(f, "contact store crypto error"),
            ContactStoreError::InvalidRecord => write!(f, "invalid contact record"),
            ContactStoreError::AlreadyProvisioned => write!(f, "contact store already provisioned"),
            ContactStoreError::NotProvisioned => write!(f, "contact store not provisioned"),
        }
    }
}
