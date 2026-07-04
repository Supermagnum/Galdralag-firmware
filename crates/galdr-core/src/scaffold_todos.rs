//! Contract tests: privileged scaffold paths must fail closed until Xous servers exist.

use crate::GaldrError;

/// Placeholder for future `vaultd` / `pind` / `usbd` IPC wiring.
fn privileged_xous_server_scaffold() -> Result<(), GaldrError> {
    Err(GaldrError::PrivilegedOperationDenied)
}

#[test]
fn privileged_xous_server_scaffold_is_fail_closed() {
    assert_eq!(
        privileged_xous_server_scaffold(),
        Err(GaldrError::PrivilegedOperationDenied)
    );
    assert!(
        GaldrError::PrivilegedOperationDenied.is_permanent_denial(),
        "stub denials must not be retried as pending work"
    );
}
