//! Galdralag USB CCID service entry point.
//!
//! This crate wires the CCID class driver to the Xous USB service.
//! It requires the `xous-bsp` feature and xous-core USB service crates
//! which are not yet part of this workspace.
//!
//! See docs/XOUS_CCID_INTEGRATION.md for the wiring pattern.

fn main() {
    // Wiring follows docs/XOUS_CCID_INTEGRATION.md:
    //
    // 1. xous_usb::get_allocator()
    // 2. OpenPgpVaultBackend::new(vault_storage, pin_storage, trng, ...)
    // 3. CcidClass::new(&alloc, OpenPgpCcidDispatcher::new(backend))
    // 4. UsbDeviceBuilder::new(..., UsbVidPid(0x20A0, 0x42B3)).build()
    // 5. poll loop + Xous IPC message handler
    todo!("wire xous-core USB service — see docs/XOUS_CCID_INTEGRATION.md")
}
