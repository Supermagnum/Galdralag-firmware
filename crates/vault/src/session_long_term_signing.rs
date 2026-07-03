//! Plaintext Brainpool long-term signing key scalars in [`VaultStorage`] for session authentication.
//!
//! **Security:** production images should wrap these scalars with AEAD; this layout is a minimal
//! contract for integration tests and early bring-up. Region is disjoint from [`crate::rsa_vault`].

use crate::brainpool384::BrainpoolP384SigningKey;
use crate::ecdsa_brainpool::BrainpoolSigningKey;
use crate::rsa_vault::KeySlot;
use galdr_core::hal::VaultStorage;

const SESSION_LT_MAGIC: &[u8; 4] = b"GLTS";
/// Bytes reserved per slot (scalar + header).
const SESSION_LT_SLOT_BYTES: usize = 512;
/// Base offset for session long-term signing keys (after public-key table in layout sketches).
pub const SESSION_LT_REGION_BASE: u64 = 0x100_000;

/// Long-term signing key material for authenticated ephemeral ECDH (one curve per slot).
pub enum SessionLongTermSigningKey {
    /// Brainpool P-256r1 ECDSA-SHA256 (handshake uses SHA256 transcript hash for all curves).
    P256(BrainpoolSigningKey),
    /// Brainpool P-384r1.
    P384(BrainpoolP384SigningKey),
}

/// Errors from session long-term signing key persistence.
#[derive(Debug, Eq, PartialEq)]
pub enum SessionLongTermSigningVaultError {
    /// Slot already contains a key and `overwrite` was false.
    SlotOccupied,
    /// Slot is empty or unreadable.
    SlotEmpty,
    /// Stored curve byte or scalar length invalid.
    InvalidEncoding,
    /// Underlying storage error.
    StorageError,
    /// Scalar out of range for the curve.
    InvalidScalar,
}

fn slot_offset(slot: &KeySlot) -> u64 {
    SESSION_LT_REGION_BASE
        .saturating_add(u64::from(slot.0).saturating_mul(SESSION_LT_SLOT_BYTES as u64))
}

/// Store a plaintext signing key scalar at `slot` (tests / provisioning only unless wrapped upstream).
pub fn vault_store_session_long_term_signing_key<S: VaultStorage>(
    storage: &mut S,
    slot: &KeySlot,
    key: &SessionLongTermSigningKey,
    overwrite: bool,
) -> Result<(), SessionLongTermSigningVaultError> {
    let off = slot_offset(slot);
    let mut probe = [0u8; 4];
    storage
        .read(off, &mut probe)
        .map_err(|_| SessionLongTermSigningVaultError::StorageError)?;
    if probe == *SESSION_LT_MAGIC && !overwrite {
        return Err(SessionLongTermSigningVaultError::SlotOccupied);
    }
    let (curve_id, scalar_buf): (u8, [u8; 64]) = match key {
        SessionLongTermSigningKey::P256(k) => {
            let b = k.to_scalar_bytes_for_test();
            let mut a = [0u8; 64];
            a[..32].copy_from_slice(&b);
            (1, a)
        }
        SessionLongTermSigningKey::P384(k) => {
            let b = k.to_scalar_bytes_for_test();
            let mut a = [0u8; 64];
            a[..48].copy_from_slice(&b);
            (2, a)
        }
    };
    let slen = match curve_id {
        1 => 32usize,
        2 => 48usize,
        _ => return Err(SessionLongTermSigningVaultError::InvalidEncoding),
    };
    let scalar = &scalar_buf[..slen];
    let mut buf = [0u8; SESSION_LT_SLOT_BYTES];
    buf[0..4].copy_from_slice(SESSION_LT_MAGIC);
    buf[4] = curve_id;
    buf[5] = scalar.len() as u8;
    buf[6..6 + scalar.len()].copy_from_slice(scalar);
    storage
        .write(off, &buf)
        .map_err(|_| SessionLongTermSigningVaultError::StorageError)?;
    Ok(())
}

/// Load the signing key at `slot`. `expected_curve` is the wire id (`1`/`2`).
pub fn vault_load_session_long_term_signing_key<S: VaultStorage>(
    storage: &S,
    slot: &KeySlot,
    expected_curve: u8,
) -> Result<SessionLongTermSigningKey, SessionLongTermSigningVaultError> {
    let off = slot_offset(slot);
    let mut buf = [0u8; SESSION_LT_SLOT_BYTES];
    storage
        .read(off, &mut buf)
        .map_err(|_| SessionLongTermSigningVaultError::StorageError)?;
    if buf[0..4] != *SESSION_LT_MAGIC {
        return Err(SessionLongTermSigningVaultError::SlotEmpty);
    }
    let curve_id = buf[4];
    if curve_id != expected_curve {
        return Err(SessionLongTermSigningVaultError::InvalidEncoding);
    }
    let slen = buf[5] as usize;
    if slen == 0 || slen > 64 || 6 + slen > SESSION_LT_SLOT_BYTES {
        return Err(SessionLongTermSigningVaultError::InvalidEncoding);
    }
    let scalar = &buf[6..6 + slen];
    match curve_id {
        1 => {
            if slen != 32 {
                return Err(SessionLongTermSigningVaultError::InvalidEncoding);
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(scalar);
            let sk = BrainpoolSigningKey::from_scalar_bytes_for_test(&a)
                .map_err(|_| SessionLongTermSigningVaultError::InvalidScalar)?;
            Ok(SessionLongTermSigningKey::P256(sk))
        }
        2 => {
            if slen != 48 {
                return Err(SessionLongTermSigningVaultError::InvalidEncoding);
            }
            let mut a = [0u8; 48];
            a.copy_from_slice(scalar);
            let sk = BrainpoolP384SigningKey::from_scalar_bytes_for_test(&a)
                .map_err(|_| SessionLongTermSigningVaultError::InvalidScalar)?;
            Ok(SessionLongTermSigningKey::P384(sk))
        }
        _ => Err(SessionLongTermSigningVaultError::InvalidEncoding),
    }
}
