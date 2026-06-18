# ESP32-CAM finger vein device

## Summary

Open-hardware finger vein capture platform based on **ESP32-S**, **OV2640** image sensor, near-infrared illumination, and USB serial to the host. Source materials and publication: **IEEE Transactions on Instrumentation and Measurement**, DOI [10.1109/TIM.2023.3324681](https://doi.org/10.1109/TIM.2023.3324681) (CC BY 4.0). Full PCB Gerbers, 3D case files, firmware, and PC software are published with the paper.

## Hardware

- **MCU:** ESP32-S series SoC
- **Imaging:** OV2640 with NIR-sensitive path and NIR LED transillumination (LEDs on one side of the finger, camera on the other)
- **Host link:** USB serial

## Recognition pipeline

Published baseline uses **Maximum Curvature (MC)** / **Miura Match (MM)** vein-pattern extraction and matching; reported **HTER** about **2.8%** in the paper (hardware and dataset dependent; not a warranty for any derivative build).

## Liveness

**Vascular pulse detection:** compare consecutive frames for frame-to-frame variation in vein appearance consistent with blood flow. Static presentation attacks (printed photos, fixed moulds, non-perfused material) lack this variation. False accept/ reject rates under attack must be measured per ISO/IEC 30107-3 on your deployment hardware.

## USB / serial protocol (integration)

**Status:** The driver crate `crates/biometric-fingervein` exposes a structure and `BiometricBackendDriver` implementation. The **command octet stream** expected from the ESP32 firmware should be documented alongside the published PC reference software from the paper repository.

Documented command classes (to be aligned with firmware releases):

| Command class | Purpose |
|---------------|---------|
| `CAPTURE` | Acquire NIR frame(s) for match or enrollment |
| `ENROLL` | Collect `samples` templates and return fused raw template bytes |
| `MATCH` | Accept nonce + encrypted (or host-supplied) reference blob; return device-signed `SignedMatchResult` CBOR |
| `GET_PUBKEY` | Return 32-byte Ed25519 public key (compressed encoding as used in the wire format) |
| `PING` | Health check for `probe()` |

Exact framing (COBS, length-prefix, SLIP, etc.) must match the ESP32 firmware build; treat the published companion PC tool as the normative byte-level reference until the project pins a version here.

## Ed25519 signing key

- Generated on-device using the ESP32 hardware RNG at first provisioning.
- Private key stored in ESP32 flash; **must not** be exportable in production configuration.
- Host learns only the **public key** during provisioning (`GET_PUBKEY` or `galdrad` provisioning flow).

## `galdrad` integration

Rust driver: `crates/biometric-fingervein/`. Host daemon `galdrad` is responsible for nonce issuance, forwarding encrypted templates from the token, signature verification, liveness and score policy, and only then releasing the biometric session HMAC for PIN APDU wrapping.

## Limitations

- Single finger only (per device geometry).
- Outdoor strong-sunlight environments can degrade NIR contrast.
- Requires USB connection to the host running `galdrad`.
- End-to-end operation on Baochip-1x tokens awaits hardware (Q2) and CCID integration.

## References

- [docs/BIOMETRIC_API.md](BIOMETRIC_API.md)
- [docs/BIOMETRIC_TESTING.md](BIOMETRIC_TESTING.md)
