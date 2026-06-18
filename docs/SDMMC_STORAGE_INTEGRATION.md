# `embedded-sdmmc` and SD card as optional bulk storage (PSRAM alternative)

This document explains how to add **removable SD / microSD** storage using the Rust **`embedded-sdmmc`** ecosystem, and how that role **replaces or complements** optional **PSRAM** chips described in [Psram.md](Psram.md). Nothing here is wired into this repository’s tree yet; **`psram-store`** in the design docs is a **QSPI PSRAM** path. The **same product slot** (“optional bulk decoy volume after unlock”) can be implemented on **microSD + SPI** instead of **PSRAM + QSPI** if the board carries a **suitable card reader** and firmware uses a **block device** abstraction.

---

## Role vs PSRAM

| Aspect | PSRAM (design) | SD / microSD (`embedded-sdmmc`) |
|--------|----------------|----------------------------------|
| Bus | QSPI, on-board chip | Typically **SPI** (or SDIO if you add a different driver) |
| Removable | No | Yes (user can swap cards) |
| Power / size | Fixed footprint | **Reader + socket** replace PSRAM **footprint** on the BOM |
| Firmware shape | Probe JEDEC, `BlockDevice` over QSPI | Initialise **SD card**, expose **`BlockDevice`** |
| Policy | [Psram.md](Psram.md): decoy volume, **no encryption** on bulk path by design | Same **product policy** if this LUN is still a **decoy**; treat removable media as **untrusted** |

Replacing PSRAM with SD means: **no QSPI PSRAM IC**; instead a **microSD holder** (push-push or hinged) and **level shifters** if the SoC I/O is not 3.3 V. The **security token** (vault, PIN, OpenPGP) is unchanged; only the **optional bulk** path moves to removable storage.

---

## Crate: `embedded-sdmmc`

The community crate **[embedded-sdmmc](https://crates.io/crates/embedded-sdmmc)** (Rust Embedded) implements an **`SdCard`** type that speaks the **SD/MMC protocol** over **SPI** using traits from **`embedded-hal`**:

- **`embedded_hal::spi::SpiDevice`** (or blocking SPI traits, depending on version) for the bus,
- A **chip-select** **`OutputPin`** for the SD socket’s **CS** line.

It provides **block-oriented** read/write (`BlockDevice` / `Block` traits in the `embedded_sdmmc` API — check the exact version on crates.io for your `embedded-hal` 0.2 vs 1.x alignment).

**Typical wiring (SPI mode):**

- **MOSI, MISO, SCK, CS** to the microSD socket (SPI mode pins per SD specification),
- **3.3 V** supply and **decoupling** at the socket,
- **Pull-ups** on lines as required by the SD physical spec for your connector.

**Initialization sequence** (conceptual): SPI low speed → `SdCard::new(...)` → increase clock after card is ready → expose **512-byte sectors** (or the crate’s block size) to your storage stack.

---

## HAL and integration steps (firmware)

1. **Board support:** In the **Xous / BSP** layer, implement or reuse an **SPI master** driver for the pins routed to the **microSD** socket.
2. **Chip select:** Dedicated **GPIO** for **CS**; never share CS with unrelated devices without muxing rules.
3. **Dependency:** Add **`embedded-sdmmc`** (and matching **`embedded-hal`** / **`embedded-hal-async`** if used) to the **firmware** `Cargo.toml` with versions **pinned** and tested on hardware.
4. **Block layer:** Wrap **`SdCard`** in the same **logical interface** you use for the optional bulk volume (the design’s **`psram-store`**-style **mount / unmount** and **LUN gating** in [Psram.md](Psram.md) / [dev-ref.md](dev-ref.md)). You may:

   - Introduce a **`BulkStorage`** trait implemented by **either** QSPI PSRAM **or** SPI SD, **or**
   - Build two product SKUs: **one** firmware image for PSRAM boards, **one** for SD boards, with **compile-time** selection.

5. **Absent card:** Probe for card presence (GPIO **card detect** if wired, or **init failure**). Behaviour must match the **graceful degradation** contract: **no optional LUN** when no card or failed init — token functions **without** bulk storage (same idea as **PSRAM absent** in [Psram.md](Psram.md)).

6. **Removable media risks:** Users can insert **hostile** cards. **Do not** store vault keys on SD without a full threat-model review; for the **decoy-only** policy, the card holds **only** unremarkable data, consistent with PSRAM decoy.

---

## “Suitable reader”

- **MicroSD socket** with **SPI** pins broken out (most modules are **SPI-compatible** in **SPI mode**).
- ** SDIO** or **SDMMC peripheral** mode is **not** covered by `embedded-sdmmc` (that crate is **SPI-centric**). For **SDIO**, you need a **different driver** (vendor HAL or `sdmmc` crate variants for your SoC). This document focuses on the **common Rust path** (`embedded-sdmmc` + SPI).
- **Mechanical:** Latched or push-push socket suitable for **portable device** vibration; **ESD** protection per your hardware team’s rules.

---

## Host side

- When the token exposes **USB mass-storage** over the **SD** volume, the **host** sees a normal **removable disk**; **no special driver** beyond OS USB mass-storage.
- For **development**, **USB SD card readers** on a PC are unrelated to **embedded-sdmmc**; they use **USB mass-storage** on the host. The **embedded** crate is for the **token firmware** talking to the **SD socket** over **SPI**.

---

## Containers and CI

- **embedded-sdmmc** is **`no_std`** firmware code; it does not run inside a **Docker** “container” for the token itself. **Containers** are useful for **building** firmware (`rustup`, `riscv32` target) or for **host** tests that **mock** `BlockDevice` without real silicon.

---

## Summary

- **`embedded-sdmmc`** + **SPI** + **microSD socket** can implement the **optional bulk** role that [Psram.md](Psram.md) assigns to **PSRAM**, **replacing** the PSRAM chip(s) with a **card reader** on the BOM.
- **Integrate** via **`embedded-hal`** SPI, **CS** GPIO, and a **block-device** layer that **mounts** only after **unlock**, same **policy** as the PSRAM design.
- ** SDIO** / **eMMC** is a **different** integration (SoC-specific); **SPI + embedded-sdmmc** is the portable Rust path documented here.

---

## Related documentation

- [Psram.md](Psram.md) — Optional PSRAM decoy volume and `psram-store` design intent.
- [NFC_PN532_INTEGRATION.md](NFC_PN532_INTEGRATION.md) — NFC at the door (orthogonal optional interface).
- [dev-ref.md](dev-ref.md) — `psram-store` and USB personality overview.
- [ARCHITECTURE.md](ARCHITECTURE.md) — High-level firmware layout.
