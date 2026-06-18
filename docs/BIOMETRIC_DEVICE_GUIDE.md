# Adding a New Biometric Backend

## Overview

Step-by-step guide for implementing support for a new biometric device in the Galdralag biometric pre-gate. Any device that implements the `BiometricBackendDriver` trait and produces a correctly signed `SignedMatchResult` can serve as a backend.

## Table of contents

- Requirements
- Implementing the driver crate
- Mock implementation for test-hal
- Writing tests
- PAD testing requirements
- Documentation checklist
- Provisioning and enrollment

## Requirements

A compliant biometric backend must:

1. Implement `BiometricBackendDriver` from `crates/biometric-api`
2. Produce `SignedMatchResult` in CBOR format (RFC 8949)
3. Sign results with Ed25519 (RFC 8032) using a key generated on-device
4. Implement liveness / presentation attack detection
5. Set `liveness = true` only when a live biometric is confirmed
6. Never retain the reference template after a match attempt
7. Pass all PAD tests in `crates/biometric-api/tests/pad.rs`
8. Provide a `MockXxx` implementation gated on `#[cfg(feature = "test-hal")]`
9. Use only audited workspace cryptographic crates — no new crypto in-tree
10. Be fully open source — no closed SDK dependencies

## Step-by-step

### 1. Create the crate

```bash
mkdir crates/biometric-<name>
# Add to workspace Cargo.toml
```

### 2. Implement BiometricBackendDriver

```rust
use biometric_api::{BiometricBackend, BiometricBackendDriver, BiometricError, Modality, SignedMatchResult};

pub struct MyDevice { /* ... */ }

impl BiometricBackendDriver for MyDevice {
    fn backend(&self) -> BiometricBackend {
        // Add a new enum variant in biometric-api if needed
        todo!()
    }

    fn authenticate(
        &self,
        nonce: &[u8; 32],
        encrypted_template: &[u8],
    ) -> Result<SignedMatchResult, BiometricError> {
        todo!()
    }

    fn enroll(&self, samples: usize) -> Result<Vec<u8>, BiometricError> {
        todo!()
    }

    fn device_pubkey(&self) -> [u8; 32] {
        todo!()
    }

    fn probe(&self) -> Result<(), BiometricError> {
        todo!()
    }
}
```

### 3. Implement MockMyDevice for test-hal

```rust
#[cfg(feature = "test-hal")]
pub struct MockMyDevice {
    pub force_match: bool,
    pub force_liveness: bool,
    pub force_score: f32,
    pub signing_key: ed25519_dalek::SigningKey,
}

#[cfg(feature = "test-hal")]
impl BiometricBackendDriver for MockMyDevice {
    // ...
}
```

### 4. Write tests

At minimum, implement all tests listed in [docs/BIOMETRIC_TESTING.md](BIOMETRIC_TESTING.md) for your backend, using `MockMyDevice`.

### 5. PAD testing

Your device must demonstrate:

- APCER = 0% against all attack types the mock simulates
- Liveness flag correctly set from device hardware

Document the liveness detection method used and its known limitations.

### 6. Documentation

Create `docs/<NAME>_DEVICE.md` covering:

- Hardware description and where to obtain it
- USB / serial / socket protocol to communicate with the device
- How the device performs liveness detection
- How the device generates and protects its Ed25519 signing key
- Provisioning steps specific to this device
- Known limitations

Add the device to the backends table in [docs/BIOMETRIC_API.md](BIOMETRIC_API.md). Add the crate to [docs/BIOMETRIC_TESTING.md](BIOMETRIC_TESTING.md) under Running the tests. Add glossary entries for any new terms to [docs/GLOSSARY.md](GLOSSARY.md).

### 7. Provisioning

Design-target host command (not necessarily implemented yet):

```bash
galdra biometric provision \
  --backend <name> \
  --device-pubkey <path> \
  --threshold <0.0-1.0> \
  --liveness required
```
