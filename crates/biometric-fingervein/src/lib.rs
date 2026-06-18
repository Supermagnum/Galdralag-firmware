//! ESP32-CAM open finger-vein device driver (host).
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

/// USB serial / HID handle to the ESP32-CAM device (stub until hardware transport lands).
pub struct FingerVeinDevice {
    usb_path: Arc<Mutex<Option<String>>>,
    signing_key: SigningKey,
    #[allow(dead_code)]
    device_id: [u8; 16],
}

impl FingerVeinDevice {
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self {
            usb_path: Arc::new(Mutex::new(None)),
            signing_key: SigningKey::generate(&mut rng),
            device_id: [0u8; 16],
        }
    }

    pub fn connect(&mut self, usb_path: &str) -> Result<(), BiometricError> {
        let mut g = self.usb_path.lock().map_err(|_| BiometricError::HardwareError(1))?;
        *g = Some(usb_path.to_string());
        Ok(())
    }

    pub fn disconnect(&mut self) {
        if let Ok(mut g) = self.usb_path.lock() {
            g.take();
        }
    }

    fn connected(&self) -> bool {
        match self.usb_path.lock() {
            Ok(g) => g.is_some(),
            Err(_) => false,
        }
    }
}

impl BiometricBackendDriver for FingerVeinDevice {
    fn backend(&self) -> BiometricBackend {
        BiometricBackend::FingerVein
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
        Err(BiometricError::HardwareError(2))
    }

    fn enroll(&self, samples: usize) -> Result<Vec<u8>, BiometricError> {
        let _ = samples;
        if !self.connected() {
            return Err(BiometricError::DeviceNotConnected);
        }
        Err(BiometricError::HardwareError(3))
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
pub struct MockFingerVeinDevice {
    pub force_match: bool,
    pub force_liveness: bool,
    pub force_score: f32,
    pub signing_key: SigningKey,
    pub device_id: [u8; 16],
    pub threshold: f32,
}

#[cfg(feature = "test-hal")]
impl MockFingerVeinDevice {
    pub fn new(signing_key: SigningKey) -> Self {
        let mut device_id = [0u8; 16];
        device_id[..8].copy_from_slice(b"fvmock01");
        Self {
            force_match: true,
            force_liveness: true,
            force_score: 0.95,
            signing_key,
            device_id,
            threshold: 0.7,
        }
    }
}

#[cfg(feature = "test-hal")]
impl BiometricBackendDriver for MockFingerVeinDevice {
    fn backend(&self) -> BiometricBackend {
        BiometricBackend::FingerVein
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
            backend: BiometricBackend::FingerVein,
            nonce: *nonce,
            timestamp: now,
            matched: self.force_match,
            score: self.force_score,
            threshold: self.threshold,
            liveness: self.force_liveness,
            modalities: vec![Modality::FingerVein],
        };
        sign_match_result(payload, &self.signing_key)
    }

    fn enroll(&self, samples: usize) -> Result<Vec<u8>, BiometricError> {
        let mut v = Vec::with_capacity(samples * 16);
        for i in 0..samples {
            v.extend_from_slice(&(i as u64).to_le_bytes());
            v.extend_from_slice(b"fingervein tpl");
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
