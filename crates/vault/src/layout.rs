//! Fixed RRAM offsets for vault subsystems (sketches; align with platform map).

use crate::public_key_vault::PUBLIC_KEY_REGION_BASE;

/// Reserved span for the public-key DER table (see `public_key_vault.rs`).
pub const PUBLIC_KEY_TABLE_BYTES: usize = 64 * 1024;

/// Bytes reserved per sealed OpenPGP private-key blob (see `sealed_key`).
pub const SEALED_BLOB_BYTES: usize = 93;

/// Sealed OpenPGP SIG slot (AEAD blob).
pub const SEALED_SIG_OFFSET: usize = PUBLIC_KEY_REGION_BASE as usize + PUBLIC_KEY_TABLE_BYTES;
/// Sealed OpenPGP DEC slot.
pub const SEALED_DEC_OFFSET: usize = SEALED_SIG_OFFSET + SEALED_BLOB_BYTES;
/// Sealed OpenPGP AUT slot.
pub const SEALED_AUT_OFFSET: usize = SEALED_DEC_OFFSET + SEALED_BLOB_BYTES;

/// Byte past the last sealed OpenPGP cell (exclusive end for `VaultStorage` sizing).
pub const SEALED_KEY_REGION_END: usize = SEALED_AUT_OFFSET + SEALED_BLOB_BYTES;
