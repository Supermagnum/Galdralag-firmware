//! USB token communication (Phase 1 stub — no hardware attached).

use crate::GaldraError;
use zeroize::Zeroizing;

/// Opaque handle to a Galdralag token (stub never connects).
pub struct Device {
    _private: (),
}

/// Runtime lock / firmware summary for `device status`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DeviceStatus {
    /// Whether a token is connected.
    pub connected: bool,
    /// Whether the token requires PIN unlock.
    pub locked: bool,
    /// Firmware version string when known.
    pub firmware_version: Option<String>,
}

/// Static information about the connected token.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DeviceInfo {
    /// Serial number when exposed by firmware.
    pub serial: Option<String>,
    /// Firmware version string.
    pub firmware_version: String,
    /// Total key slots available.
    pub key_slot_count: u32,
    /// Number of occupied key slots.
    pub key_slots_used: u32,
}

/// One row from `key list`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct KeySlotInfo {
    /// Slot index.
    pub slot: u32,
    /// Human-readable key type label.
    pub key_type: String,
    /// OpenPGP fingerprint hex.
    pub fingerprint: String,
    /// Creation timestamp string when known.
    pub created_at: Option<String>,
}

/// Exported public key encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// OpenPGP transferable public key.
    Pgp,
    /// PEM encoding.
    Pem,
    /// DER encoding.
    Der,
}

/// Provisioning-time PIN policy bounds enforced on the host before USB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionPolicy {
    /// Allowed PIN attempts before lockout (3–10 inclusive).
    pub pin_attempts: u8,
    /// Minimum PIN length enforced by policy (5–32 inclusive).
    pub min_pin_length: u8,
}

/// PIN buffer that zeroises on drop.
pub struct PinBuffer(zeroize::Zeroizing<String>);

impl PinBuffer {
    /// Validate and wrap a PIN string.
    pub fn new(pin: String) -> Result<Self, GaldraError> {
        if pin.len() < 5 {
            return Err(GaldraError::PinTooShort);
        }
        if !pin.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(GaldraError::PinNotAlphanumeric);
        }
        Ok(PinBuffer(Zeroizing::new(pin)))
    }

    /// Borrow the validated PIN (do not log or persist).
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl ProvisionPolicy {
    /// Validate bounds for host-side checks before sending to firmware.
    pub fn validate(&self) -> Result<(), GaldraError> {
        if !(3..=10).contains(&self.pin_attempts) {
            return Err(GaldraError::Config(
                "pin_attempts must be between 3 and 10 inclusive".to_string(),
            ));
        }
        if !(5..=32).contains(&self.min_pin_length) {
            return Err(GaldraError::Config(
                "min_pin_length must be between 5 and 32 inclusive".to_string(),
            ));
        }
        Ok(())
    }
}

impl Device {
    /// Connect to the first available Galdralag token over USB.
    pub fn connect() -> Result<Self, GaldraError> {
        Err(GaldraError::DeviceNotConnected)
    }

    /// Current high-level device status.
    pub fn status(&self) -> Result<DeviceStatus, GaldraError> {
        Err(GaldraError::DeviceNotConnected)
    }

    /// Unlock the token using the user-supplied PIN.
    pub fn unlock(&self, _pin: &PinBuffer) -> Result<(), GaldraError> {
        Err(GaldraError::DeviceNotConnected)
    }

    /// Lock the token (clears session keys on device).
    pub fn lock(&self) -> Result<(), GaldraError> {
        Err(GaldraError::DeviceNotConnected)
    }

    /// Detailed device information.
    pub fn info(&self) -> Result<DeviceInfo, GaldraError> {
        Err(GaldraError::DeviceNotConnected)
    }

    /// Enumerate key slots present on the token.
    pub fn key_list(&self) -> Result<Vec<KeySlotInfo>, GaldraError> {
        Err(GaldraError::DeviceNotConnected)
    }

    /// Export the public key for a slot.
    pub fn key_export_public(&self, _slot: u32, _format: KeyFormat) -> Result<Vec<u8>, GaldraError> {
        Err(GaldraError::DeviceNotConnected)
    }

    /// Delete a key from a slot.
    pub fn key_delete(&self, _slot: u32) -> Result<(), GaldraError> {
        Err(GaldraError::DeviceNotConnected)
    }

    /// Permanently erase all device state.
    pub fn zeroise(&self) -> Result<(), GaldraError> {
        Err(GaldraError::DeviceNotConnected)
    }

    /// Provision a blank token (policy + device key).
    pub fn provision(&self, _pin: &PinBuffer, _policy: ProvisionPolicy) -> Result<(), GaldraError> {
        Err(GaldraError::DeviceNotConnected)
    }

    /// Generate random bytes for a message session key (TRNG-backed on device).
    pub fn generate_session_key(&self) -> Result<Vec<u8>, GaldraError> {
        Err(GaldraError::DeviceNotConnected)
    }

    /// Serial number exposed by firmware, if any.
    pub fn serial(&self) -> Option<String> {
        None
    }
}
