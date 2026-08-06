//! Dabao bring-up OpenPGP backend when RRAM mapping is unavailable.
//!
//! Answers SELECT / GET DATA for default DOs without a vault. Crypto and PIN
//! operations return unsupported / conditions-not-satisfied status words.

use galdr_core::HalError;
use galdr_vault::KeyPurpose;
use heapless::Vec;
use usb_personality::openpgp::{
    AlgorithmAttributes, OpenPgpAudit, OpenPgpBackend, OpenPgpBackendError, OpenPgpKeySlot,
    StatusWord, DEFAULT_PW_STATUS_BYTES,
};

/// In-memory OpenPGP backend for Dabao when [`galdr_core::UnsupportedVaultStorage`] would be used.
///
/// Holds default PW status (`0xC4`) and signature counter (`0x93`) so `gpg --card-status`
/// can progress past empty mandatory DOs without RRAM.
pub struct DabaoBringupBackend {
    aid: [u8; 16],
    pw_status: [u8; 7],
    sig_counter: [u8; 3],
    /// Keeps the unused stub storage visible for auditors of the Dabao fallback path.
    _unsupported_vault: galdr_core::UnsupportedVaultStorage,
}

impl DabaoBringupBackend {
    pub fn new(aid: [u8; 16]) -> Self {
        Self {
            aid,
            pw_status: DEFAULT_PW_STATUS_BYTES,
            sig_counter: [0, 0, 0],
            _unsupported_vault: galdr_core::UnsupportedVaultStorage,
        }
    }
}

impl OpenPgpAudit for DabaoBringupBackend {
    fn log_event(&mut self, _code: u32) {}
}

impl OpenPgpBackend for DabaoBringupBackend {
    fn is_termination_state(&self) -> bool {
        false
    }

    fn aid_bytes(&self) -> &[u8] {
        &self.aid
    }

    fn pw_status_bytes(&self) -> [u8; 7] {
        self.pw_status
    }

    fn user_pin_retries_remaining(&self) -> u8 {
        self.pw_status[4]
    }

    fn admin_pin_retries_remaining(&self) -> u8 {
        self.pw_status[6]
    }

    fn verify_pw1_sign(&mut self, _pin: &[u8]) -> Result<(), OpenPgpBackendError> {
        Err(OpenPgpBackendError::Status(
            StatusWord::ConditionsNotSatisfied,
        ))
    }

    fn verify_pw1_other(&mut self, _pin: &[u8]) -> Result<(), OpenPgpBackendError> {
        Err(OpenPgpBackendError::Status(
            StatusWord::ConditionsNotSatisfied,
        ))
    }

    fn verify_pw3(&mut self, _pin: &[u8]) -> Result<(), OpenPgpBackendError> {
        Err(OpenPgpBackendError::Status(
            StatusWord::ConditionsNotSatisfied,
        ))
    }

    fn change_pin(
        &mut self,
        _pw3: bool,
        _old_pin: &[u8],
        _new_pin: &[u8],
    ) -> Result<(), OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn set_pw1_verifier_admin_only(&mut self, _new_pin: &[u8]) -> Result<(), OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn reset_pw1_retry_counter(&mut self) -> Result<(), OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn get_do(&self, tag: u16) -> Result<Vec<u8, 512>, OpenPgpBackendError> {
        let mut out = Vec::new();
        let bytes: &[u8] = match tag {
            0xC4 => &self.pw_status,
            0x93 => &self.sig_counter,
            0x4F => &self.aid,
            _ => &[],
        };
        for b in bytes {
            out.push(*b)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        }
        Ok(out)
    }

    fn put_do(&mut self, _tag: u16, _value: &[u8]) -> Result<(), OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn algorithm_attributes(&self, slot: OpenPgpKeySlot) -> AlgorithmAttributes {
        let mut oid: Vec<u8, 16> = Vec::new();
        for b in usb_personality::openpgp::dos::curve_oids::BRAINPOOL_P256R1 {
            let _ = oid.push(*b);
        }
        match slot {
            OpenPgpKeySlot::Dec => AlgorithmAttributes::Ecdh { curve_oid: oid },
            _ => AlgorithmAttributes::Ecdsa { curve_oid: oid },
        }
    }

    fn pso_sign_hash(&mut self, _hash: &[u8]) -> Result<Vec<u8, 512>, OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn pso_decipher(&mut self, _data: &[u8]) -> Result<Vec<u8, 512>, OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn ecdh_dec(
        &mut self,
        _slot_purpose: KeyPurpose,
        _peer_public_key: &[u8],
    ) -> Result<Vec<u8, 64>, OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn get_challenge(&mut self, _len: usize) -> Result<Vec<u8, 64>, OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn ed25519_sign(
        &mut self,
        _purpose: KeyPurpose,
        _message: &[u8],
    ) -> Result<Vec<u8, 64>, OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn x25519_ecdh(
        &mut self,
        _purpose: KeyPurpose,
        _peer_public_key: &[u8],
    ) -> Result<Vec<u8, 32>, OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn internal_authenticate(
        &mut self,
        _challenge: &[u8],
    ) -> Result<Vec<u8, 512>, OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn generate_or_read_key(
        &mut self,
        _p1: u8,
        _slot: OpenPgpKeySlot,
    ) -> Result<Vec<u8, 512>, OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn increment_signature_counter(&mut self) -> Result<(), OpenPgpBackendError> {
        Err(OpenPgpBackendError::Hal(HalError::Unsupported))
    }

    fn on_lock_disconnect(&mut self) {}
}
