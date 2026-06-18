//! Biometric pre-gate wire types, CBOR (RFC 8949) framing, and Ed25519 (RFC 8032) helpers.
#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use cbor4ii::serde::{from_slice as cbor_from_slice, to_vec as cbor_to_vec};
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// Wire format major version for [`MatchPayload`].
pub const MATCH_PAYLOAD_VERSION: u8 = 1;

/// Backend identifier (provisioned per device class).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum BiometricBackend {
    FingerVein = 1,
    SweetPlatform = 2,
}

/// Sampled modality flags carried in [`MatchPayload`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Modality {
    FingerVein = 1,
    PalmVein = 2,
    Palmprint = 3,
}

/// Signed payload (serialised as CBOR map before signing).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MatchPayload {
    pub version: u8,
    pub device_id: [u8; 16],
    pub backend: BiometricBackend,
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub matched: bool,
    pub score: f32,
    pub threshold: f32,
    pub liveness: bool,
    pub modalities: Vec<Modality>,
}

/// Outer signed structure returned by a biometric device.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedMatchResult {
    pub payload: MatchPayload,
    pub signature: [u8; 64],
}

/// CBOR transport view with variable-length signature bytes (validated to 64).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SignedMatchWire {
    payload: MatchPayload,
    signature: Vec<u8>,
}

/// Session token material the token firmware verifies (host places raw HMAC in PIN flow).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BiometricSessionToken {
    pub hmac: [u8; 32],
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BiometricError {
    DeviceNotConnected,
    LivenessCheckFailed,
    MatchFailed,
    SignatureInvalid,
    NonceMismatch,
    TimestampExpired,
    EnrollmentNotFound,
    StorageFull,
    CborError,
    /// Reserved for transport / HAL-specific faults (code is opaque to API consumers).
    HardwareError(u32),
}

impl fmt::Display for BiometricError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BiometricError::DeviceNotConnected => write!(f, "device not connected"),
            BiometricError::LivenessCheckFailed => write!(f, "liveness check failed"),
            BiometricError::MatchFailed => write!(f, "match failed or below threshold"),
            BiometricError::SignatureInvalid => write!(f, "Ed25519 signature invalid"),
            BiometricError::NonceMismatch => write!(f, "nonce mismatch"),
            BiometricError::TimestampExpired => write!(f, "timestamp outside allowed window"),
            BiometricError::EnrollmentNotFound => write!(f, "enrollment not found"),
            BiometricError::StorageFull => write!(f, "template storage full"),
            BiometricError::CborError => write!(f, "CBOR encode or decode error"),
            BiometricError::HardwareError(c) => write!(f, "hardware error ({c})"),
        }
    }
}

impl From<SignatureError> for BiometricError {
    fn from(_: SignatureError) -> Self {
        BiometricError::SignatureInvalid
    }
}

/// Serialises [`MatchPayload`] to CBOR bytes (the octet string signed by the device).
pub fn match_payload_cbor_bytes(payload: &MatchPayload) -> Result<Vec<u8>, BiometricError> {
    cbor_to_vec(Vec::new(), payload).map_err(|_| BiometricError::CborError)
}

/// Verifies `signature` over the canonical CBOR encoding of `payload`.
pub fn verify_match_payload_signature(
    payload: &MatchPayload,
    signature: &[u8; 64],
    verifying_key: &VerifyingKey,
) -> Result<(), BiometricError> {
    let msg = match_payload_cbor_bytes(payload)?;
    let sig = Signature::from_slice(signature.as_slice())?;
    verifying_key
        .verify(msg.as_slice(), &sig)
        .map_err(|_| BiometricError::SignatureInvalid)
}

/// Signs `payload` with `signing_key` (test / mock backends only in this repository).
pub fn sign_match_result(
    payload: MatchPayload,
    signing_key: &SigningKey,
) -> Result<SignedMatchResult, BiometricError> {
    let msg = match_payload_cbor_bytes(&payload)?;
    let sig = signing_key.sign(msg.as_slice());
    let mut signature = [0u8; 64];
    signature.copy_from_slice(sig.to_bytes().as_slice());
    Ok(SignedMatchResult { payload, signature })
}

/// Serialises [`SignedMatchResult`] as a CBOR map suitable for logging or transport.
pub fn signed_match_to_cbor(result: &SignedMatchResult) -> Result<Vec<u8>, BiometricError> {
    let wire = SignedMatchWire {
        payload: result.payload.clone(),
        signature: result.signature.to_vec(),
    };
    cbor_to_vec(Vec::new(), &wire).map_err(|_| BiometricError::CborError)
}

/// Decodes [`SignedMatchResult`] from CBOR bytes (host / fuzz entry point).
pub fn signed_match_from_bytes(data: &[u8]) -> Result<SignedMatchResult, BiometricError> {
    let wire: SignedMatchWire = cbor_from_slice(data).map_err(|_| BiometricError::CborError)?;
    if wire.signature.len() != 64 {
        return Err(BiometricError::CborError);
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(wire.signature.as_slice());
    Ok(SignedMatchResult {
        payload: wire.payload,
        signature,
    })
}

/// Host-side (`galdrad`) checks before treating a biometric event as gating a PIN forward.
pub fn galdrad_validate_match_result(
    result: &SignedMatchResult,
    verifying_key: &VerifyingKey,
    expected_nonce: &[u8; 32],
    now_secs: u64,
    max_age_secs: u64,
) -> Result<(), BiometricError> {
    verify_match_payload_signature(&result.payload, &result.signature, verifying_key)?;
    if result.payload.version != MATCH_PAYLOAD_VERSION {
        return Err(BiometricError::CborError);
    }
    if result.payload.nonce != *expected_nonce {
        return Err(BiometricError::NonceMismatch);
    }
    if now_secs.saturating_sub(result.payload.timestamp) > max_age_secs {
        return Err(BiometricError::TimestampExpired);
    }
    if !result.payload.liveness {
        return Err(BiometricError::LivenessCheckFailed);
    }
    if !result.payload.matched {
        return Err(BiometricError::MatchFailed);
    }
    if result.payload.score < result.payload.threshold {
        return Err(BiometricError::MatchFailed);
    }
    Ok(())
}

/// Fuzz / hardening helper: parse and cryptographically verify without panicking.
pub fn fuzz_try_verify_signed_match(
    data: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<(), BiometricError> {
    let sm = signed_match_from_bytes(data)?;
    // Random inputs must not verify; Ok only for a valid cryptographic match.
    verify_match_payload_signature(&sm.payload, &sm.signature, verifying_key)?;
    galdrad_validate_match_result(
        &sm,
        verifying_key,
        &sm.payload.nonce,
        sm.payload.timestamp,
        3600,
    )
}

/// Trait implemented by host-side biometric drivers (`galdrad` integration).
pub trait BiometricBackendDriver: Send + Sync {
    fn backend(&self) -> BiometricBackend;

    /// Request live capture and match against `encrypted_template` (opaque to the device).
    fn authenticate(
        &self,
        nonce: &[u8; 32],
        encrypted_template: &[u8],
    ) -> Result<SignedMatchResult, BiometricError>;

    /// Capture enrollment samples; returns raw template bytes for host encryption before RRAM write.
    fn enroll(&self, samples: usize) -> Result<Vec<u8>, BiometricError>;

    fn device_pubkey(&self) -> [u8; 32];

    fn probe(&self) -> Result<(), BiometricError>;
}

#[cfg(test)]
mod tests;
