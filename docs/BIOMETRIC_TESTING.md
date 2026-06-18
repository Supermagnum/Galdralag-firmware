# Biometric Testing

## Overview

Documents the test methodology, frameworks, and datasets used to validate the optional biometric authentication layer.

## Table of contents

- Standards
- Test suites
- PAD testing (ISO/IEC 30107-3)
- Accuracy benchmarking
- Hardware vs simulation
- Running the tests
- Interpreting results
- Adding a new backend

## Standards

| Standard | Scope |
|----------|-------|
| ISO/IEC 30107-3 | Presentation attack detection testing methodology |
| ISO/IEC 19794-9 | Vascular biometric data interchange format |

## PAD metrics (ISO/IEC 30107-3)

| Metric | Definition | Target (mock) | Target (hardware, TBD) |
|--------|-----------|---------------|------------------------|
| APCER | Attack Presentation Classification Error Rate | 0.0% | TBD after Q2 |
| BPCER | Bona fide Presentation Classification Error Rate | 0.0% | TBD after Q2 |
| ACER | (APCER + BPCER) / 2 | 0.0% | TBD after Q2 |

APCER and BPCER values with real hardware and real attack material must be measured and documented before any production deployment claim is made.

## Reference datasets

| Dataset | Backend | Source |
|---------|---------|--------|
| CandyFV | sweet platform | https://www.idiap.ch/en/scientific-research/data/candyfv |
| ESP32-CAM device dataset | Finger vein | IEEE TIM DOI: 10.1109/TIM.2023.3324681 |

## Running the tests

```bash
# Unit and integration tests
cargo test -p biometric-api
cargo test -p biometric-vault
cargo test -p biometric-fingervein --features test-hal
cargo test -p biometric-sweet --features test-hal

# PAD tests
cargo test -p biometric-api --test pad

# Timing / dudect
cargo run -p xtask -- timing-test biometric

# Fuzz
cargo run -p xtask -- fuzz biometric_dispatch 60
```

Convenience orchestration (same crates as `test-all` biometric step):

```bash
cargo run -p xtask -- test-biometric
```

## Hardware vs simulation

All tests currently run against mock backends using `test-hal`. Once Baochip-1x hardware (Q2) and physical biometric devices are available:

1. Connect the ESP32-CAM finger vein device or sweet platform
2. Run `cargo test -p biometric-fingervein` (without `test-hal` feature) when USB drivers are wired
3. Measure APCER/BPCER with real presentation attack material
4. Update PAD metric targets in this document and in test assertions

## Interpreting results

- Failing unit or integration tests indicate a regression in wire format, cryptography, or validation logic.
- PAD tests with mocks are expected to show APCER = 0% and BPCER = 0% for the simulated scenarios; hardware will differ.
- Dudect harnesses are statistical; occasional borderline *t*-statistics warrant a re-run, not an automatic security claim.

## Adding a new biometric backend

See [docs/BIOMETRIC_DEVICE_GUIDE.md](BIOMETRIC_DEVICE_GUIDE.md).
