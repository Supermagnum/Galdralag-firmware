//! OpenPGP card session state (PIN flags, APDU chaining).

#![deny(unsafe_code)]

use heapless::Vec;

/// OpenPGP card session state. Reset on power-off or token lock.
#[derive(Debug)]
pub struct CardState {
    /// User PIN (PW1) verified for signing (PSO:CDS).
    pw1_verified_sign: bool,
    /// User PIN (PW1) verified for other operations (decipher, auth).
    pw1_verified_other: bool,
    /// Admin PIN (PW3) verified.
    pw3_verified: bool,
    /// Command chaining buffer for multi-APDU operations.
    pub chain_buffer: Vec<u8, 2048>,
    /// Response buffer for GET RESPONSE chaining.
    pub response_buffer: Vec<u8, 2048>,
    /// Read offset into `response_buffer` for GET RESPONSE.
    pub response_offset: usize,
    /// MANAGE SECURITY ENVIRONMENT: active key reference for DEC slot (OpenPGP P2=0xB8).
    pub mse_dec_key_ref: Option<u8>,
    /// MSE: active key reference for SIG slot (P2=0xB6).
    pub mse_sig_key_ref: Option<u8>,
    /// MSE: active key reference for AUT slot (P2=0xA4).
    pub mse_aut_key_ref: Option<u8>,
}

impl CardState {
    /// New session state (no PINs verified).
    pub fn new() -> Self {
        Self {
            pw1_verified_sign: false,
            pw1_verified_other: false,
            pw3_verified: false,
            chain_buffer: Vec::new(),
            response_buffer: Vec::new(),
            response_offset: 0,
            mse_dec_key_ref: None,
            mse_sig_key_ref: None,
            mse_aut_key_ref: None,
        }
    }

    /// Reset all verification flags and buffers (power-off, lock, card removal).
    pub fn reset(&mut self) {
        self.pw1_verified_sign = false;
        self.pw1_verified_other = false;
        self.pw3_verified = false;
        self.chain_buffer.clear();
        self.response_buffer.clear();
        self.response_offset = 0;
        self.mse_dec_key_ref = None;
        self.mse_sig_key_ref = None;
        self.mse_aut_key_ref = None;
    }

    /// PW1 for signing (mode 0x81): resets after each PSO:CDS when consumed.
    pub fn set_pw1_sign(&mut self, verified: bool) {
        self.pw1_verified_sign = verified;
    }

    pub fn is_pw1_sign_verified(&self) -> bool {
        self.pw1_verified_sign
    }

    /// Clear sign verification after PSO:CDS (OpenPGP default PW1 mode).
    pub fn consume_pw1_sign(&mut self) {
        self.pw1_verified_sign = false;
    }

    /// PW1 for other ops (mode 0x82): persists until reset.
    pub fn set_pw1_other(&mut self, verified: bool) {
        self.pw1_verified_other = verified;
    }

    pub fn is_pw1_other_verified(&self) -> bool {
        self.pw1_verified_other
    }

    /// PW3 (admin PIN).
    pub fn set_pw3(&mut self, verified: bool) {
        self.pw3_verified = verified;
    }

    pub fn is_pw3_verified(&self) -> bool {
        self.pw3_verified
    }
}

impl Default for CardState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pw1_sign_consumed_after_sign() {
        let mut s = CardState::new();
        s.set_pw1_sign(true);
        assert!(s.is_pw1_sign_verified());
        s.consume_pw1_sign();
        assert!(!s.is_pw1_sign_verified());
    }

    #[test]
    fn pw1_other_persists() {
        let mut s = CardState::new();
        s.set_pw1_other(true);
        assert!(s.is_pw1_other_verified());
        assert!(s.is_pw1_other_verified());
    }

    #[test]
    fn reset_clears_all() {
        let mut s = CardState::new();
        s.set_pw1_sign(true);
        s.set_pw1_other(true);
        s.set_pw3(true);
        s.reset();
        assert!(!s.is_pw1_sign_verified());
        assert!(!s.is_pw1_other_verified());
        assert!(!s.is_pw3_verified());
    }
}
