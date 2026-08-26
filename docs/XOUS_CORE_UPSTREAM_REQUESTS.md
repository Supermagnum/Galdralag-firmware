# Upstream requests for xous-core (do not patch from Galdralag)

Galdralag tasks must **not** edit the sibling or nested `xous-core` trees when working
under the “xous-core is read-only” constraint. This file records changes that belong
in **xous-core** (fork branch `feature/usb-bao1x-ccid-openpgp`, upstream
[PR #937](https://github.com/betrusted-io/xous-core/pull/937) / issue
[#875](https://github.com/betrusted-io/xous-core/issues/875)).

Last reviewed against local sibling HEAD that includes `ccid-openpgp` and
`Opcode::CcidRxDeferred = 640` / `CcidTx = 642` in
`services/usb-bao1x/src/api.rs`.

---

## 1. Document Persona A vs CDC provisioning in upstream docs

**Where:** `docs/CCID_PROTOCOL_AND_HIL.md`, `docs/CCID_TEST_REPORT.md`, and any
README text that still implies a USB CDC provisioning serial on CCID images.

**Need:** State clearly that feature `ccid-openpgp` alone (Persona A / `dabao-ccid`)
does **not** allocate a provisioning CDC-ACM interface and does **not** write PDDB
`usb.ccid` / `OKV1` from the USB path. Offline helpers live under feature
`ccid-pddb` (`services/usb-bao1x/src/ccid_store.rs`).

**Why:** Galdralag historically documented CDC two-line PIN provisioning as the
primary path; that mismatches the branch as built for Dabao.

---

## 2. Optional: stock `dabao-ccid` convenience for Galdralag

**Where:** `xtask/src/main.rs` arm `Some("dabao-ccid")` (~792–830).

**Current:** Positional cratespecs are already added as **Flash boot services**
(good). The stock package list still has no `galdralag-service` unless the caller
passes a cratespec.

**Need (optional):** Document in xous-core help/`README-baochip.md` that
`cargo xtask dabao-ccid galdralag-service:/abs/path` is the supported way to
include an out-of-tree OpenPGP handler; or add a named example in docs.

**Why:** Plain `dabao-ccid` remains transport-only (inline ATR / GetSlotStatus);
operators must know to pass the cratespec. Galdralag ships
`scripts/build_dabao_ccid_image.sh` for this without editing xtask.

---

## 3. ATR / GetSlotStatus ownership policy (document upstream)

**Where:** `services/usb-bao1x/src/ccid_transport.rs` (`drain_complete_messages`:
inline `is_get_slot_status` / `is_icc_power_on`).

**Current:** Transport answers `0x65` and `0x62` in IRQ context and does **not**
enqueue those frames to `CcidRxDeferred`.

**Need:** Document that external handlers must treat XfrBlock (and other non-inline
messages) as their domain; they will **not** see PowerOn/GetSlotStatus when inline
answers are enabled. If product policy later wants Galdralag-owned ATR, upstream
must stop answering `0x62` inline (or make it a feature flag).

**Why:** Avoid double-answer races. Galdralag’s `OpenPgpCcidDispatcher` still answers 0x62/0x65 for in-process `CcidClass`. Xous `galdralag-service` / `galdralag-stub` **do not `CcidTx`** those opcodes (`PcToRdr::answered_inline_by_usb_bao1x`).

---

## 4. CCID IPC first-PID lock (security)

**Where:** `services/usb-bao1x/src/main.rs` handlers for `CcidRxDeferred` / `CcidTx`
(compare to `U2fRxDeferred` / `U2fTx` first-PID lock).

**Need:** Mirror FIDO-style first-registrant PID lock so a second process cannot
steal CCID IPC (`Denied`).

**Why:** Threat model T7 in Galdralag `docs/THREAT_MODEL.md` — host session tokens
alone do not stop another Xous process from driving PIN APDUs.

---

## 5. Host libccid Info.plist (`1D50:6197`)

**Where:** Host OS / packaging (not firmware). PR #937 already notes the local
Python `Info.plist` edit for `ifd-ccid`.

**Need:** Upstream or distro packaging note so operators do not miss this step.

**Why:** Without it, `pcscd` may not attach to Baochip Dabao CCID.

---

## 6. Items that are *not* xous-core (tracked in Galdralag only)

| Item | Galdralag home |
|------|----------------|
| FSFE/GnuPG OpenPGP manufacturer ID; stop misusing USB VID `0x20A0` as AID manufacturer bytes | `docs/OPENPGP_CARD.md`, `docs/future-todo.md`, README known limitations |
| `galdra device status` vendor/AID filter | host tools |
| Dabao lab PIN defaults / docs for no-CDC images | README, `services/galdralag/README.md` |

---

## 7. Host `pcscd` WriteUSB timeout after ATR (lab 2026-08-18)

**Where:** Host `pcscd` / libccid against `usb:1d50/6197` (Dabao serial `HBZFHW`). Device-side likely `services/usb-bao1x` CCID bulk OUT after inline IccPowerOn.

**Observed:** First `pcsc_scan` after plug shows Card inserted + OpenPGP ATR `3B DA 18 FF 81 B1 FE 75 1F 03 00 31 C5 73 C0 01 40 00 90 00 0C`. Then `gpg --card-status` fails (`Ingen slik enhet`); subsequent `pcsc_scan` is **Status unavailable**. `pcscd` logs `ccid_usb.c:WriteUSB() LIBUSB_ERROR_TIMEOUT` and `Card not transacted: 612`. Unplug/replug restores one ATR; `systemctl restart pcscd` without a USB replug did not.

**Investigation (read-only, xous-core `80921c682`):** Branch tip equals the lab commit — no newer `feature/usb-bao1x-ccid-openpgp` commit to rebuild against. Bulk OUT re-arm **is present** at this commit (introduced in `f265ee346`, ancestor of `80921c682`):

- `prime_bulk_out()` / `force_prime_bulk_out()` in `ccid_transport.rs`
- Inline GetSlotStatus / IccPowerOn path calls `force_prime_bulk_out` before queuing bulk IN (`drain_complete_messages` Step::Inline; `endpoint_out_with_bus` before/after `poll_bulk_in`)
- Periodic `CcidPrimeBulkOut` (100 ms) in `main.rs`
- Re-arm after `CcidTx`; prime on deferred listener connect; initial prime in `set_device_address` (`bao1x-hal` `driver.rs`)
- `attach_force_bus` wired from `hw.rs`

xous-core `docs/CCID_TEST_REPORT.md` documents ATR + `pcsc_scan` + `RFAddReader` with an **out-of-tree APDU stub**; full GnuPG is listed as not yet tested. **Not a missing re-arm / version-mismatch problem** — next diagnostics: Galdralag `XfrBlock` / `CcidTx` path, or subtler Corigine `enq != deq` force-prime no-op after inline IN (see `force_prime_bulk_out` gate in `driver.rs`).

**Need:** Device-side bulk OUT / TRB state after inline IccPowerOn ATR (not missing re-arm at `80921c682`). Phase 2 (2026-08-18): **`galdralag-stub` image fails identically** — rules out Galdralag vault/handler. Host pyusb direct test blocked while `pcscd` holds the interface (`Resource busy`). Optional: `irq-pending-trace` build + `tools/bulk_trb_trace_poll.py` on Dabao; or stop `pcscd` and run `tools/ccid_hil/ccid_usb.py` round-trip.

**Why:** Blocks `gpg --card-status` even when `galdralag-service` or `galdralag-stub` is in the image.

---

## 8. Deferred XfrBlock round-trip fails after inline path works (Phase 2 confirmed)

**Where:** `usb-bao1x` deferred IPC (`CcidRxDeferred` / `CcidTx`) + handler (`galdralag-stub` / `galdralag-service`). Inline GetSlotStatus / IccPowerOn in `ccid_transport.rs` are fine.

**Observed (2026-08-18, fresh flash, `galdralag-stub`):** First `pcsc_scan` shows Card inserted + OpenPGP ATR; same scan session then **Status unavailable**. `opensc-tool` / `gpg` fail. Same pattern as `galdralag-service` image — **not handler-specific**.

**Direct pyusb (pcscd stopped, CCID if0 claimed, no `set_configuration`):** After replug with `pcscd.service` + `pcscd.socket` stopped:

| Step | Result |
|------|--------|
| GetSlotStatus | **OK** — `81000000000000000000` (inline `usb-bao1x`) |
| IccPowerOn / ATR | **OK** — 31 bytes, OpenPGP ATR in `RDR_to_PC_DataBlock` |
| XfrBlock SELECT | **FAIL** — bulk IN read timeout (errno 110) |

Bulk OUT **write** for GetSlotStatus/IccPowerOn works. Failure is on the **first deferred `XfrBlock`** (`CcidRxDeferred` → `galdralag-stub` → `CcidTx`), not on missing bulk OUT re-arm for inline opcodes.

**Marker stub retest (2026-08-18, `xous.uf2` `c6d1641f…`):** Stub answers every XfrBlock with `CA FE 90 00` without parsing. Pyusb: XfrBlock bulk OUT OK (26 bytes in 0.000s); bulk IN timeout after 8 s (**no `CA FE 90 00`**). Inline GetSlotStatus probe after failure also times out on bulk IN. Conclusion: host delivers XfrBlock on bulk OUT; device never returns deferred bulk IN — **not invokable from host**; points to xous-core `CcidRxDeferred` / `CcidTx` (or bulk IN after deferred handler), not Galdralag vault/stub logic. Host `find_ccid_device()` still fails with Resource busy if `set_configuration()` is called while HID ifaces use `usbhid` — use `scripts/dabao_ccid_pyusb_smoke.sh`.

**Need:** Trace first `XfrBlock` on device: `IrqCcidRx` → `CcidRxDeferred` delivery to stub PID; stub `CcidTx` → bulk IN; listener registration / first-PID lock in `usb-bao1x`. Optional UART `xous-log` from `galdralag-stub` during pyusb smoke.

**Why:** xous-core HIL validated inline ATR/RFAddReader only; deferred handler path was not hardware-confirmed on this host.
