//! OpenPGP card backend: PIN verification, key ops, and DO storage (vault integration point).

#![deny(unsafe_code)]

use heapless::Vec;

use super::dos::AlgorithmAttributes;
use galdr_core::HalError;
use galdr_vault::KeyPurpose;

/// Slot identifiers for OpenPGP key operations (SIG / DEC / AUT).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenPgpKeySlot {
    /// Signature key (PSO:CDS).
    Sig,
    /// Decryption / ECDH (PSO:DECIPHER).
    Dec,
    /// Authentication (INTERNAL AUTHENTICATE).
    Aut,
}

/// Errors from vault or policy layers mapped for APDU responses.
#[derive(Debug)]
pub enum OpenPgpBackendError {
    /// Map directly to status words.
    Status(super::error::StatusWord),
    /// HAL / vault error.
    Hal(HalError),
}

impl From<HalError> for OpenPgpBackendError {
    fn from(e: HalError) -> Self {
        OpenPgpBackendError::Hal(e)
    }
}

/// Audit hook for signing, decryption, authentication, and key generation.
pub trait OpenPgpAudit: Sized {
    /// Record a security-relevant event (implementation may log to vault audit region).
    fn log_event(&mut self, code: u32);
}

/// No-op audit sink for bring-up.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullAudit;

impl OpenPgpAudit for NullAudit {
    fn log_event(&mut self, _code: u32) {}
}

/// Pluggable backend: integrate with `vault`, `pin-policy`, and crypto crates in firmware.
pub trait OpenPgpBackend: OpenPgpAudit {
    /// True after permanent lock / zeroisation (card in termination state).
    fn is_termination_state(&self) -> bool;

    /// OpenPGP AID bytes (tag 0x4F).
    fn aid_bytes(&self) -> &[u8];

    /// PW status bytes (tag 0xC4): PIN lengths and retry counters per device policy.
    fn pw_status_bytes(&self) -> [u8; 7];

    /// Remaining user PIN attempts (for 0x63Cx).
    fn user_pin_retries_remaining(&self) -> u8;

    /// Remaining admin PIN attempts.
    fn admin_pin_retries_remaining(&self) -> u8;

    /// VERIFY PW1 for signing (P2=0x81).
    fn verify_pw1_sign(&mut self, pin: &[u8]) -> Result<(), OpenPgpBackendError>;

    /// VERIFY PW1 for other (P2=0x82).
    fn verify_pw1_other(&mut self, pin: &[u8]) -> Result<(), OpenPgpBackendError>;

    /// VERIFY PW3 (P2=0x83).
    fn verify_pw3(&mut self, pin: &[u8]) -> Result<(), OpenPgpBackendError>;

    /// CHANGE REFERENCE DATA for PW1 or PW3.
    fn change_pin(
        &mut self,
        pw3: bool,
        old_pin: &[u8],
        new_pin: &[u8],
    ) -> Result<(), OpenPgpBackendError>;

    /// Set new PW1 verifier without old PIN (INS 0x2C; PW3 verified by session state).
    fn set_pw1_verifier_admin_only(&mut self, new_pin: &[u8]) -> Result<(), OpenPgpBackendError>;

    /// Reset PW1 retry counter to its provisioned maximum (INS 0x2C after new-PIN write).
    fn reset_pw1_retry_counter(&mut self) -> Result<(), OpenPgpBackendError>;

    /// Read a single DO value (may be empty).
    fn get_do(&self, tag: u16) -> Result<Vec<u8, 512>, OpenPgpBackendError>;

    /// Write DO if policy allows.
    fn put_do(&mut self, tag: u16, value: &[u8]) -> Result<(), OpenPgpBackendError>;

    /// Algorithm attributes for slot.
    fn algorithm_attributes(&self, slot: OpenPgpKeySlot) -> AlgorithmAttributes;

    /// PSO:CDS — sign hash (host pre-hash).
    fn pso_sign_hash(&mut self, hash: &[u8]) -> Result<Vec<u8, 512>, OpenPgpBackendError>;

    /// PSO:DECIPHER — decrypt or ECDH.
    fn pso_decipher(&mut self, data: &[u8]) -> Result<Vec<u8, 512>, OpenPgpBackendError>;

    /// PSO:DECIPHER — ECDH shared secret (raw, no HKDF). Host derives session keys.
    fn ecdh_dec(
        &mut self,
        slot_purpose: KeyPurpose,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8, 64>, OpenPgpBackendError>;

    /// GET CHALLENGE — random bytes from the device TRNG (INS 0x84).
    fn get_challenge(&mut self, len: usize) -> Result<Vec<u8, 64>, OpenPgpBackendError>;

    /// PSO:CDS / INTERNAL AUTHENTICATE — Ed25519 signature over the message bytes.
    fn ed25519_sign(
        &mut self,
        purpose: KeyPurpose,
        message: &[u8],
    ) -> Result<Vec<u8, 64>, OpenPgpBackendError>;

    /// PSO:DECIPHER — X25519 ECDH (32-byte shared secret).
    fn x25519_ecdh(
        &mut self,
        purpose: KeyPurpose,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8, 32>, OpenPgpBackendError>;

    /// INTERNAL AUTHENTICATE.
    fn internal_authenticate(&mut self, challenge: &[u8]) -> Result<Vec<u8, 512>, OpenPgpBackendError>;

    /// GENERATE ASYMMETRIC KEY PAIR (P1=0x80) or read public (P1=0x81).
    fn generate_or_read_key(
        &mut self,
        p1: u8,
        slot: OpenPgpKeySlot,
    ) -> Result<Vec<u8, 512>, OpenPgpBackendError>;

    /// Increment signature counter after PSO:CDS.
    fn increment_signature_counter(&mut self) -> Result<(), OpenPgpBackendError>;

    /// Notify token lock: clear host-visible card state (integrator triggers USB re-enumeration).
    fn on_lock_disconnect(&mut self);
}

impl OpenPgpBackendError {
    /// Map to APDU status word.
    pub fn to_status_word(&self) -> super::error::StatusWord {
        match self {
            OpenPgpBackendError::Status(s) => *s,
            OpenPgpBackendError::Hal(_) => super::error::StatusWord::ExecutionError,
        }
    }
}
