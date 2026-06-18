//! Contract tests: scaffold code paths must fail loudly until Xous services exist.
//!
//! **TODO (developer):** Remove `#[should_panic]` tests once real IPC handlers return
//! `GaldrError::NotImplemented` instead of `todo!`, and add integration tests against hardware
//! doubles.

#[test]
#[should_panic(expected = "not yet implemented")]
fn document_stub_panic_contract() {
    todo!("not yet implemented — wire vaultd / pind / usbd Xous servers");
}
