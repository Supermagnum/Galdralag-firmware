//! Provisioned PIN policy record: verifier digest and attempt threshold stored together in RRAM.
//!
//! The threshold is set once at provisioning and must be in **3..=10** (see [`pin_policy`] constants).
//! The host cannot change it without authenticated provisioning.

use galdr_core::hal::VaultStorage;
use pin_policy::{
    PinPolicyConfig, MAX_PROVISIONED_PIN_ATTEMPTS, MIN_PROVISIONED_PIN_ATTEMPTS,
};

/// Magic and version for the on-device policy blob.
const VAULT_PIN_POLICY_MAGIC: &[u8; 4] = b"GPPL";
const VAULT_PIN_POLICY_VERSION: u8 = 1;

/// Fixed size written at a layout-defined offset (e.g. start of policy region).
pub const VAULT_PIN_POLICY_RECORD_BYTES: usize = 64;

/// Decoded provisioned PIN policy from vault storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultPinPolicyRecord {
    /// Stored verifier (e.g. SHA-256 of salted PIN or PBKDF output); interpretation is product-specific.
    pub pin_verifier_sha256: [u8; 32],
    /// Persisted attempt ceiling; must satisfy provisioning bounds.
    pub max_pin_attempts: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultPinPolicyError {
    BadMagic,
    BadVersion,
    MaxAttemptsOutOfRange,
    StorageError,
}

impl VaultPinPolicyRecord {
    /// Encode for [`VaultStorage::write`]. Validates attempt bounds.
    pub fn encode(&self) -> Result<[u8; VAULT_PIN_POLICY_RECORD_BYTES], VaultPinPolicyError> {
        PinPolicyConfig::try_with_max_attempts(self.max_pin_attempts)
            .map_err(|_| VaultPinPolicyError::MaxAttemptsOutOfRange)?;
        let mut out = [0u8; VAULT_PIN_POLICY_RECORD_BYTES];
        out[0..4].copy_from_slice(VAULT_PIN_POLICY_MAGIC);
        out[4] = VAULT_PIN_POLICY_VERSION;
        out[5..37].copy_from_slice(&self.pin_verifier_sha256);
        out[37..41].copy_from_slice(&self.max_pin_attempts.to_le_bytes());
        Ok(out)
    }

    /// Decode from a policy-region read.
    pub fn decode(buf: &[u8; VAULT_PIN_POLICY_RECORD_BYTES]) -> Result<Self, VaultPinPolicyError> {
        if buf[0..4] != *VAULT_PIN_POLICY_MAGIC {
            return Err(VaultPinPolicyError::BadMagic);
        }
        if buf[4] != VAULT_PIN_POLICY_VERSION {
            return Err(VaultPinPolicyError::BadVersion);
        }
        let mut pin_verifier_sha256 = [0u8; 32];
        pin_verifier_sha256.copy_from_slice(&buf[5..37]);
        let max_pin_attempts = u32::from_le_bytes(buf[37..41].try_into().unwrap());
        PinPolicyConfig::try_with_max_attempts(max_pin_attempts)
            .map_err(|_| VaultPinPolicyError::MaxAttemptsOutOfRange)?;
        Ok(Self {
            pin_verifier_sha256,
            max_pin_attempts,
        })
    }

    /// Build the in-memory [`PinPolicyConfig`] for the state machine.
    pub fn to_pin_policy_config(&self) -> PinPolicyConfig {
        PinPolicyConfig {
            max_attempts: self.max_pin_attempts,
        }
    }
}

/// Read policy from `offset` in `storage`.
pub fn vault_read_pin_policy<S: VaultStorage>(
    storage: &S,
    offset: u64,
) -> Result<VaultPinPolicyRecord, VaultPinPolicyError> {
    let mut buf = [0u8; VAULT_PIN_POLICY_RECORD_BYTES];
    storage
        .read(offset, &mut buf)
        .map_err(|_| VaultPinPolicyError::StorageError)?;
    VaultPinPolicyRecord::decode(&buf)
}

/// Write policy to `offset` in `storage`.
pub fn vault_write_pin_policy<S: VaultStorage>(
    storage: &mut S,
    offset: u64,
    record: &VaultPinPolicyRecord,
) -> Result<(), VaultPinPolicyError> {
    let enc = record.encode()?;
    storage
        .write(offset, &enc)
        .map_err(|_| VaultPinPolicyError::StorageError)
}

/// Documented provisioning bounds (re-export for integrators).
pub const fn provisioned_attempts_range() -> (u32, u32) {
    (MIN_PROVISIONED_PIN_ATTEMPTS, MAX_PROVISIONED_PIN_ATTEMPTS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_default_attempts() {
        let r = VaultPinPolicyRecord {
            pin_verifier_sha256: [0x42u8; 32],
            max_pin_attempts: pin_policy::DEFAULT_MAX_PIN_ATTEMPTS,
        };
        let enc = r.encode().unwrap();
        let d = VaultPinPolicyRecord::decode(&enc).unwrap();
        assert_eq!(r, d);
    }

    #[test]
    fn round_trip_ten() {
        let r = VaultPinPolicyRecord {
            pin_verifier_sha256: [1u8; 32],
            max_pin_attempts: 10,
        };
        let enc = r.encode().unwrap();
        let d = VaultPinPolicyRecord::decode(&enc).unwrap();
        assert_eq!(r, d);
    }

    #[test]
    fn encode_rejects_two() {
        let r = VaultPinPolicyRecord {
            pin_verifier_sha256: [0u8; 32],
            max_pin_attempts: 2,
        };
        assert_eq!(r.encode(), Err(VaultPinPolicyError::MaxAttemptsOutOfRange));
    }
}
