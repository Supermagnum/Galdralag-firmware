# PN532 / NFC integration (door access and quorum)

This document describes **how to add NFC support** around a **PN532**-class front end, typical **host software** options (**libnfc** and Rust-facing paths), and how that fits a **physical presence + Shamir + identity + PIN/biometric** quorum model for **drive key reconstruction** and **door access**. Nothing in this file is implemented in the firmware tree yet; it is an **integration guide** for hardware and software that will sit **beside** the token firmware ([vault](ARCHITECTURE.md), [Shamir](API_REFERENCE.md), USB/CCID: [RRAM_LAYOUT.md](RRAM_LAYOUT.md), `usb-personality`, `baochip-openpgp`, Xous `usb-bao1x`).

---

## Goals

| Scenario | Idea |
|----------|------|
| **Quorum** | **Physical presence** (NFC tap at a reader) **plus** a **Shamir share** (on-device or carried) **plus** **Brainpool-backed identity** (certificate or key fingerprint) **plus** **PIN and/or biometric** together satisfy policy before reconstructing a **drive key** or releasing a **door unlock** authorization. |
| **Passive NFC (no USB)** | Token presents as an **NFC tag or card emulation**; a **self-powered door reader** supplies the RF field; the device is **passive** (no USB cable). |
| **USB at the door** | Token connects **USB-A** (or USB-C) to a **lock panel** that provides **power and data**; **cryptographic authentication** runs over a channel such as **USB HID** (or CCID, depending on product choices) in addition to or instead of NFC for that site. |

Exact policy (which factors are mandatory, order of operations, timeouts) belongs in product requirements and eventually in vault / host policy code.

---

## PN532 overview

The **NXP PN532** is a common **NFC controller** supporting reader/writer and card-emulation style use cases, depending on firmware and wiring. Host boards usually expose it via:

- **USB** (UART bridge, e.g. common “PN532 USB” modules),
- **UART**,
- **I2C** or **SPI** to a microcontroller or SBC.

**libnfc** ([libnfc.org](https://nfc-tools.github.io/)) is the **de facto C library** on Linux and macOS for talking to many readers, including PN532 in several configurations. It provides:

- Device enumeration,
- **ISO14443A/B** framing,
- **MIFARE Classic/Ultralight**-oriented helpers,
- Examples (`nfc-list`, `nfc-poll`, etc.) suitable as a **bring-up** path.

For **door readers** running **Linux** on the panel, **libnfc** is still the most direct path unless you implement a **kernel driver** or **pure Rust** transport yourself.

---

## Host side: libnfc

### Prerequisites (typical Linux door panel or dev PC)

1. **Packages:** `libnfc` development headers and runtime (names vary: Debian/Ubuntu `libnfc-dev`, `libnfc-bin`; Fedora `libnfc-devel`).
2. **Permissions:** udev rules so the **door service user** can open the device node (often `/dev/bus/usb/...` or a hidraw node, depending on the adapter). Model rules on vendor ID / product ID of the USB-UART chip on the PN532 board.
3. **Verify:** Run `nfc-list` with the reader connected; you should see one or more devices.

### Integration pattern

- A **long-running daemon** on the lock panel polls or waits for a **target** (the token or a phone).
- On **card detected**, the daemon performs a **challenge-response** or reads **NDEF**/custom records, then calls into your **auth stack** (validate Brainpool signature, check Shamir share index, combine with PIN collected on a keypad or biometric matcher).
- **libnfc** is **C**; link it from:

  - **C/C++** service directly, or
  - **Rust** via **`bindgen`** / **`libnfc-sys`**-style crates (search [crates.io](https://crates.io) for `libnfc` or `nfc-sys`; names and maintenance status change — **evaluate** any crate before production), or
  - **Python** / other FFI for prototypes.

### Limitations to plan for

- **libnfc** abstracts readers; **PN532-specific** features (GPIO, IRQ lines) may need **datasheet-level** code if you do not use a stock USB module.
- **Card emulation** on the **token** side (phone or device acts as tag) requires **firmware and antenna** support that is **not** in this repository today; the Baochip/Xous side would need a **new personality** (NFC controller driver + protocol state machine).

---

## Rust options (host or companion service)

There is **no single blessed Rust stack** in this repo. Practical approaches:

| Approach | When to use |
|----------|-------------|
| **FFI to libnfc** | Fastest path on Linux where **libnfc** already works with your PN532 USB module. Generate or hand-maintain unsafe bindings; keep the NFC I/O in a small process if you want isolation. |
| **Pure Rust `pn532` drivers** | Search **crates.io** for `pn532` and related HAL crates for **embedded** (often `embedded-hal` **I2C/UART**). Suitable if the **lock panel MCU** is Rust-only and talks to PN532 over **I2C** without libnfc. |
| **PC/SC** | If the reader presents as a **CCID** or **PC/SC** device instead of raw PN532, use **PC/SC** (`pcsc` crate on crates.io) — different hardware, same **“tap card”** UX. |
| **Container** | Run **libnfc** and a thin C or Python bridge in a **container** with **USB device passthrough** (`--device`) or **serial** forwarded; useful for CI and lab tests. The container image must include **libnfc** and **udev** rules inside or rely on host passthrough. |

Always **pin versions** and run **integration tests** on the **exact** PN532 module and kernel you ship.

---

## Firmware and token side (this repository)

Today, Galdralag firmware focuses on **RRAM vault**, **PIN policy**, **OpenPGP/CCID** ([OPENPGP_CARD.md](OPENPGP_CARD.md)), **USB personalities**, and **Shamir** in software ([API_REFERENCE.md](API_REFERENCE.md)). **NFC is not implemented.**

To support the scenarios above, a future design would likely include:

1. **NFC controller driver** (PN532 or other) on the **Xous**/BSP side: **I2C/UART** to the chip, interrupt handling, power management.
2. **Protocol layer:** e.g. **Type A** polling, **NDEF** or a **custom binary** record carrying a **challenge**, **public key fingerprint**, or **partial Shamir** metadata (never send full secrets in plaintext over NFC without encryption).
3. **Policy engine hook:** require **NFC session active** **and** **PIN verified** **and** **k-of-n Shamir** (or Brainpool-signed assertion) before releasing **drive unwrap** or **door credential**.
4. **Passive operation:** antenna and PN532 in **low-power listen** or **card emulation** mode per datasheet; **RF field** from the reader powers or wakes the analog front end — **hardware design** must match **NFC forum** requirements for the chosen mode.

Coordinate with the token’s **USB/CCID** integration ([RRAM_LAYOUT.md](RRAM_LAYOUT.md), `usb-bao1x` / `baochip-openpgp` in the main repo and xous-core) for **USB** at the door: a panel might expose **HID** for **button-less PIN** entry on host software, while the token uses **CCID** or **vendor HID** reports for **challenge-response**. Exact **USB HID** report layout would be a **separate specification** (not defined here).

---

## Deployment diagrams (logical)

### A. Normal use — passive NFC, no USB to reader

```text
[Token / phone / wearable]  ---- NFC (passive / card emulation) ---->  [Door reader: PN532 + MCU + libnfc or Rust driver]
                                                                                |
                                                                                +-- Self-powered (mains or battery)
                                                                                +-- Unlocks strike / motor on auth OK
```

The **token** does not need a USB cable to the door; **RF** carries the **limited** protocol. **Crypto** should still assume **short range** and **eavesdroppers**; use **challenge-response**, **signatures**, and **no static secrets** in clear text.

### B. USB at the door lock panel

```text
[Token]  ---- USB (power + data) ---->  [Door lock panel: Linux or RTOS]
                                              |
                                              +-- HID or CCID for crypto auth
                                              +-- May also include PN532 for dual mode (USB + tap)
```

**Power** from the panel can charge the token or run sessions **without** draining the token battery for NFC. **HID** is often used for **keyboard-class** PIN entry to the panel UI, or **custom** HID reports for **vendor auth**; align with **USB.org** HID usage and your **threat model**.

---

## Quorum example (conceptual)

```text
Physical presence (NFC tap at door)     -->  proves user is at the reader
        +
Shamir share (on token or second factor) -->  k-of-n split of drive master key material
        +
Brainpool identity (key / cert / fingerprint) -->  binds operation to the right key holder
        +
PIN / biometric                        -->  what you know / are
        =
Quorum satisfied  -->  reconstruct drive key AND/OR issue door unlock credential
```

Mapping each factor to **concrete APIs** (vault slots, `KeyPurpose`, [cipher profiles](CIPHER_PROFILES.md)) is **future work** once NFC and panel software exist.

---

## Related documentation

- [API_REFERENCE.md](API_REFERENCE.md) — Shamir and host export formats.
- [ARCHITECTURE.md](ARCHITECTURE.md) — Vault and subsystems.
- [SDMMC_STORAGE_INTEGRATION.md](SDMMC_STORAGE_INTEGRATION.md) — Optional **microSD** via **`embedded-sdmmc`** as an alternative to **PSRAM** for bulk decoy storage.
- [RRAM_LAYOUT.md](RRAM_LAYOUT.md) — OpenPGP/CCID RRAM band on Baochip; `baochip-openpgp`, `usb-bao1x`
- [GALDRA-TOOL.md](GALDRA-TOOL.md) — Host tooling and provisioning.

---

## Summary

- Use **libnfc** for **PN532** bring-up on **Linux door panels** unless you commit to a **pure Rust** embedded driver over **I2C/UART**.
- **Rust** can wrap **libnfc** via **FFI** or use **embedded PN532** crates from the ecosystem; **evaluate** crates for maintenance and safety.
- **Containers** can host **libnfc**-based services with **USB passthrough** for development.
- **This firmware** does not yet implement NFC; adding **PN532** support requires **BSP/driver work**, a **protocol**, and **policy hooks** tied to **Shamir**, **Brainpool identity**, and **PIN/biometric** as product requirements dictate.
