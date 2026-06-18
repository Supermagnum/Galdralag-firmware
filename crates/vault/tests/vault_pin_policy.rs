//! Integration: PIN policy record (verifier hash + attempt ceiling) round-trips through vault storage.

use galdr_core::fake_hal::FakeVaultStorage;
use pin_policy::DEFAULT_MAX_PIN_ATTEMPTS;
use galdr_vault::{
    vault_read_pin_policy, vault_write_pin_policy, VaultPinPolicyError, VaultPinPolicyRecord,
};

#[test]
fn provisioned_policy_persisted_with_pin_hash() {
    let mut mem = FakeVaultStorage::new(128);
    let record = VaultPinPolicyRecord {
        pin_verifier_sha256: [0xab; 32],
        max_pin_attempts: 7,
    };
    vault_write_pin_policy(&mut mem, 0, &record).expect("write");
    let loaded = vault_read_pin_policy(&mem, 0).expect("read");
    assert_eq!(loaded, record);
    assert_eq!(
        loaded.to_pin_policy_config().max_attempts,
        record.max_pin_attempts
    );
}

#[test]
fn default_attempts_three() {
    let mut mem = FakeVaultStorage::new(128);
    let record = VaultPinPolicyRecord {
        pin_verifier_sha256: [0; 32],
        max_pin_attempts: DEFAULT_MAX_PIN_ATTEMPTS,
    };
    vault_write_pin_policy(&mut mem, 0, &record).unwrap();
    let loaded = vault_read_pin_policy(&mem, 0).unwrap();
    assert_eq!(loaded.max_pin_attempts, 3);
}

#[test]
fn rejects_two_attempts_on_decode() {
    let mut raw = [0u8; 64];
    raw[0..4].copy_from_slice(b"GPPL");
    raw[4] = 1;
    raw[37..41].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(
        VaultPinPolicyRecord::decode(&raw),
        Err(VaultPinPolicyError::MaxAttemptsOutOfRange)
    );
}
