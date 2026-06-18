//! Typed errors for contact-store operations.

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
