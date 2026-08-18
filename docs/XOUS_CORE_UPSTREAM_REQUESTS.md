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
