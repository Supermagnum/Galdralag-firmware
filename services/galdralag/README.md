# Galdralag Xous USB service

The CCID USB server entry point for production firmware is not in this repository yet.

When the Xous service crate is added, implement `main` using the pattern in [docs/XOUS_CCID_INTEGRATION.md](../../docs/XOUS_CCID_INTEGRATION.md) (allocator, `OpenPgpVaultBackend`, `OpenPgpCcidDispatcher`, `CcidClass`, `UsbDeviceBuilder::poll`).
