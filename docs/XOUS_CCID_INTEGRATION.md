# Xous USB CCID integration (reference)

The Galdralag firmware runs on [Xous](https://github.com/betrusted-io/xous-core). This document describes how to wire the `usb-personality` CCID class to the Xous `usb-device` stack so a host can use GnuPG `scdaemon` over USB.

There is no `services/galdralag` crate in this repository yet; when that service exists, place the main loop in `services/galdralag/src/main.rs` (or the appropriate Xous server entry point) following the pattern below.

## Dependencies

- `usb-device` (already a workspace dependency for `usb-personality`).
- The Xous USB service / bus allocator from your board support package (see `betrusted-io/xous-core` and `xous-usb-hid` for the same `UsbClass` + `UsbDeviceBuilder::poll` pattern).

## Main loop sketch

1. Obtain the shared `UsbBusAllocator` from the Xous USB driver after registration (exact IPC or syscall depends on the BSP; mirror `xous-usb-hid` or your vendor example).
2. Build vault-backed storage handles (RRAM, TRNG, monotonic counters, zeroise hooks) and construct [`OpenPgpVaultBackend`](../../crates/usb-personality/src/openpgp/vault_backend.rs).
3. Wrap the backend in [`OpenPgpCcidDispatcher`](../../crates/usb-personality/src/openpgp/dispatch.rs).
4. Allocate [`CcidClass`](../../crates/usb-personality/src/ccid/usb_class.rs) with the allocator and dispatcher.
5. Build [`UsbDevice`](https://docs.rs/usb-device/) with [`UsbDeviceBuilder`](https://docs.rs/usb-device/), using [`USB_VID_GALDRALAG`](../../crates/usb-personality/src/ccid/mod.rs) and [`USB_PID_GALDRALAG_TOKEN`](../../crates/usb-personality/src/ccid/mod.rs) (0x20A0 / 0x42B3), plus the manufacturer/product strings from [`USB_STRING_*`](../../crates/usb-personality/src/ccid/mod.rs).
6. Poll in a loop: on each iteration call `usb_dev.poll(&mut [&mut ccid])` so `CcidClass::poll` can drain Bulk IN and `endpoint_out` can receive Bulk OUT. Interleave `xous::try_receive_message` (or your server’s IPC) for non-USB work and `xous::yield_slice()` when idle.

```rust
// Pseudocode — adapt types and IPC to your Xous USB service API.

use usb_device::class_prelude::*;
use usb_device::device::{UsbDeviceBuilder, UsbVidPid};
use usb_personality::ccid::{CcidClass, USB_PID_GALDRALAG_TOKEN, USB_VID_GALDRALAG};
use usb_personality::openpgp::{OpenPgpCcidDispatcher, OpenPgpVaultBackend};

// let usb_alloc = /* from Xous USB registration */;
// let backend = OpenPgpVaultBackend::new(/* ... */)?;
// let dispatch = OpenPgpCcidDispatcher::new(backend);
// let mut ccid = CcidClass::new(&usb_alloc, dispatch);
// let mut usb_dev = UsbDeviceBuilder::new(&usb_alloc, UsbVidPid(USB_VID_GALDRALAG, USB_PID_GALDRALAG_TOKEN))
//     .manufacturer("Galdralag Project")
//     .product("Galdralag Security Token")
//     .serial_number("00000000")
//     .device_class(0x00)
//     .build();
// loop {
//     let _ = usb_dev.poll(&mut [&mut ccid]);
//     // xous::try_receive_message(server_cid) ...
// }
```

## Class behaviour

- **Bulk OUT**: `CcidClass` accumulates PC_to_RDR frames (possibly split across 64-byte packets), parses with [`parse_pc_to_rdr`](../../crates/usb-personality/src/ccid/command.rs), and dispatches via [`OpenPgpDispatch::handle_ccid`](../../crates/usb-personality/src/openpgp/dispatch.rs).
- **Bulk IN**: Responses are sent in up to 64-byte chunks; `UsbError::WouldBlock` is retried on the next `poll`.
- **USB reset**: `CcidClass::reset` clears buffers and calls [`OpenPgpDispatch::on_usb_reset`](../../crates/usb-personality/src/openpgp/dispatch.rs) (clears [`CardState`](../../crates/usb-personality/src/openpgp/state.rs) and [`OpenPgpBackend::on_lock_disconnect`](../../crates/usb-personality/src/openpgp/backend.rs)).
