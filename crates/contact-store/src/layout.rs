//! RRAM byte offsets for the contact-store region (see `docs/RRAM_LAYOUT.md`).

/// First byte of the contact-store region (after USB CCID band, 4 KiB aligned sketch).
pub const CONTACT_STORE_BASE: u64 = 76_800;

/// One persisted contact record (`ContactRecord`).
pub const CONTACT_RECORD_BYTES: usize = 256;

/// Total contact slots (4 own-identity + 50 recipient).
pub const CONTACT_SLOT_COUNT: usize = 54;

/// Recipient slots occupy indices `4..=53`.
pub const RECIPIENT_SLOT_START: u8 = 4;

/// Number of recipient slots.
pub const RECIPIENT_SLOT_COUNT: usize = 50;

/// Span of the fixed record array in RRAM.
pub const CONTACT_RECORD_ARRAY_BYTES: usize = CONTACT_RECORD_BYTES * CONTACT_SLOT_COUNT;

/// String heap capacity in RRAM.
pub const STRING_HEAP_BYTES: u32 = 64 * 1024;

/// Public-key material region capacity in RRAM.
pub const KEY_REGION_BYTES: u32 = 64 * 1024;

/// Append-only timing log capacity in RRAM.
pub const TIMING_LOG_BYTES: u32 = 16 * 1024;

/// Offset of the record array from `CONTACT_STORE_BASE`.
pub const CONTACT_RECORD_ARRAY_OFFSET: u64 = CONTACT_STORE_BASE;

/// Offset of the string heap from `CONTACT_STORE_BASE`.
pub const STRING_HEAP_OFFSET: u64 = CONTACT_STORE_BASE + CONTACT_RECORD_ARRAY_BYTES as u64;

/// Offset of the key-material region from `CONTACT_STORE_BASE`.
pub const KEY_REGION_OFFSET: u64 = STRING_HEAP_OFFSET + STRING_HEAP_BYTES as u64;

/// Offset of the timing log from `CONTACT_STORE_BASE`.
pub const TIMING_LOG_OFFSET: u64 = KEY_REGION_OFFSET + KEY_REGION_BYTES as u64;

/// Exclusive end of the contact-store RRAM band (timing log).
pub const CONTACT_STORE_RRAM_END: u64 = TIMING_LOG_OFFSET + TIMING_LOG_BYTES as u64;

/// Always-on monotonic counter slot for contact-store provisioning (see `docs/RRAM_LAYOUT.md`).
#[allow(dead_code)]
pub const CONTACT_STORE_PROVISION_COUNTER: u32 = 7;

/// Four-byte provision marker in RRAM (`0` = not provisioned).
pub const CONTACT_STORE_PROVISION_MARKER_OFFSET: u64 = CONTACT_STORE_RRAM_END;

/// Mirrored 256-bit integrity digest (backup-register stand-in until HAL is wired).
pub const CONTACT_STORE_INTEGRITY_OFFSET: u64 = CONTACT_STORE_PROVISION_MARKER_OFFSET + 4;

/// Total span including provision marker and integrity mirror.
pub const CONTACT_STORE_END: u64 = CONTACT_STORE_INTEGRITY_OFFSET + 32;

/// Magic written to active records (`CTAC` little-endian).
pub const CONTACT_RECORD_MAGIC: u32 = 0x4341_4354;

/// Maximum public-key blob stored in the key region (RSA-4096 SPKI upper bound).
pub const MAX_PUBLIC_KEY_BYTES: usize = 768;

/// Maximum heap-backed string field length.
pub const MAX_STRING_FIELD_BYTES: u16 = 240;
