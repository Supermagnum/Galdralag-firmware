//! sweet platform full-hand scanner driver (host).
//!
//! // HARDWARE: requires Baochip-1x (Q2) and physical biometric device
//! // SIMULATION: test-hal only — not for production

use std::sync::{Arc, Mutex};

use biometric_api::{
    sign_match_result, BiometricBackend, BiometricBackendDriver, BiometricError, MatchPayload,
    Modality, SignedMatchResult, MATCH_PAYLOAD_VERSION,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

pub struct SweetPlatform {
    socket_path: Arc<Mutex<Option<String>>>,
    signing_key: SigningKey,
    #[allow(dead_code)]
    device_id: [u8; 16],
}

impl SweetPlatform {
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self {
            socket_path: Arc::new(Mutex::new(None)),
            signing_key: SigningKey::generate(&mut rng),
            device_id: [0u8; 16],
        }
    }

    pub fn connect(&mut self, socket_path: &str) -> Result<(), BiometricError> {
        let mut g = self
            .socket_path
            .lock()
            .map_err(|_| BiometricError::HardwareError(1))?;
        *g = Some(socket_path.to_string());
        Ok(())
    }

    fn connected(&self) -> bool {
        match self.socket_path.lock() {
            Ok(g) => g.is_some(),
            Err(_) => false,
        }
    }
}

impl BiometricBackendDriver for SweetPlatform {
    fn backend(&self) -> BiometricBackend {
        BiometricBackend::SweetPlatform
    }

    fn authenticate(
        &self,
        _nonce: &[u8; 32],
        encrypted_template: &[u8],
    ) -> Result<SignedMatchResult, BiometricError> {
        let _ = encrypted_template;
        if !self.connected() {
            return Err(BiometricError::DeviceNotConnected);
        }
        Err(BiometricError::HardwareError(10))
    }

    fn enroll(&self, samples: usize) -> Result<Vec<u8>, BiometricError> {
        let _ = samples;
        if !self.connected() {
            return Err(BiometricError::DeviceNotConnected);
        }
        Err(BiometricError::HardwareError(11))
    }

    fn device_pubkey(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    fn probe(&self) -> Result<(), BiometricError> {
        if self.connected() {
            Ok(())
        } else {
            Err(BiometricError::DeviceNotConnected)
        }
    }
}

#[cfg(feature = "test-hal")]
pub struct MockSweetPlatform {
    pub force_match: bool,
    pub force_liveness: bool,
    pub force_score: f32,
    pub force_modalities: Vec<Modality>,
    pub signing_key: SigningKey,
    pub device_id: [u8; 16],
    pub threshold: f32,
}

#[cfg(feature = "test-hal")]
impl MockSweetPlatform {
    pub fn new(signing_key: SigningKey) -> Self {
        let mut device_id = [0u8; 16];
        device_id[..8].copy_from_slice(b"sweetplc");
        Self {
            force_match: true,
            force_liveness: true,
            force_score: 0.99,
            force_modalities: vec![
                Modality::PalmVein,
                Modality::Palmprint,
                Modality::FingerVein,
            ],
            signing_key,
            device_id,
            threshold: 0.8,
        }
    }
}

#[cfg(feature = "test-hal")]
impl BiometricBackendDriver for MockSweetPlatform {
    fn backend(&self) -> BiometricBackend {
        BiometricBackend::SweetPlatform
    }

    fn authenticate(
        &self,
        nonce: &[u8; 32],
        encrypted_template: &[u8],
    ) -> Result<SignedMatchResult, BiometricError> {
        let _ = encrypted_template;
        let now = 1_700_000_000u64;
        let payload = MatchPayload {
            version: MATCH_PAYLOAD_VERSION,
            device_id: self.device_id,
            backend: BiometricBackend::SweetPlatform,
            nonce: *nonce,
            timestamp: now,
            matched: self.force_match,
            score: self.force_score,
            threshold: self.threshold,
            liveness: self.force_liveness,
            modalities: self.force_modalities.clone(),
        };
        sign_match_result(payload, &self.signing_key)
    }

    fn enroll(&self, samples: usize) -> Result<Vec<u8>, BiometricError> {
        let mut v = Vec::with_capacity(samples * 32);
        for i in 0..samples {
            v.extend_from_slice(&(i as u64).to_le_bytes());
            v.extend_from_slice(b"sweet multimodal template block ");
        }
        Ok(v)
    }

    fn device_pubkey(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    fn probe(&self) -> Result<(), BiometricError> {
        Ok(())
    }
}
