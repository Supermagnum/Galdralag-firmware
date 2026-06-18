# sweet platform integration

## Summary

The **sweet** platform is an open-hardware / open-software contactless hand biometrics research stack from **Idiap Research Institute**, described in *Sensors* **2025**, DOI [10.3390/s25164990](https://doi.org/10.3390/s25164990). Partial hardware design and acquisition software are publicly available; exact shipping configurations may vary by lab build.

## Hardware concept

- **Contactless** acquisition at roughly **10–12 cm** working distance (positioning matters).
- Simultaneous capture of **four fingers** and **palm**.
- **Modalities:** palm vein (NIR **850 nm** and **950 nm** channels), palmprint (RGB), finger veins (NIR).
- **3D** cues via **photometric stereo** and stereo NIR rigs as described in the publication.

## Liveness

The design combines **2D texture**, **subcutaneous vascular** (NIR vein) signals, and **3D photometric stereo** depth. Defeating all three simultaneously with commodity spoof artefacts is intended to be impractical; **measured** APCER/BPCER are still required (ISO/IEC 30107-3) before deployment claims.

## Recognition

Pipeline includes vein enhancement (e.g. autoencoder-based), MC-style vein features, and **score fusion** across modalities. Published multimodal database experiments report **EER** as low as **0.0008%** under controlled conditions; field performance will differ.

## Integration protocol (host)

**Status:** `crates/biometric-sweet` is the Rust integration point. The acquisition stack runs as a **separate process**; the driver must use an IPC surface defined by the sweet software release (typically a **Unix domain socket** path or equivalent).

| Aspect | Notes |
|--------|-------|
| **Socket path** | Configurable per installation, passed to `SweetPlatform::connect` |
| **Message format** | CBOR or length-prefixed JSON/binary as defined by the sweet release; must map to `SignedMatchResult` emitted to `galdrad` |
| **Enrollment** | Returns raw template bytes for encryption on the token |

Until a pinned sweet release is vendored in this repository, treat Idiap’s published acquisition tools as authoritative for framing and command verbs.

## Ed25519 key

Generated and stored in sweet platform hardware (or secure module attached to it, per deployment). Public key is provisioned to the token and `galdrad` like other backends.

## Dataset for benchmarking

**CandyFV** — finger vein data collected with the sweet platform from **120** subjects:  
https://www.idiap.ch/en/scientific-research/data/candyfv

## `galdrad` driver

Rust crate: `crates/biometric-sweet/`.

## Limitations

- Larger hardware footprint than a single-finger USB device.
- Requires consistent user positioning and lighting control for best results.
- Full token integration depends on Baochip-1x availability (Q2) and CCID path for template fetch.

## References

- [docs/BIOMETRIC_API.md](BIOMETRIC_API.md)
- [docs/BIOMETRIC_TESTING.md](BIOMETRIC_TESTING.md)
