use crate::{usb_exposed_secret_slice, Personality};

#[test]
fn uninformed_mass_storage_reveals_no_secret_bytes() {
    assert!(usb_exposed_secret_slice(Personality::MassStorageDecoy).is_none());
}

#[test]
fn authenticated_path_still_hides_raw_keys_in_scaffold() {
    assert!(usb_exposed_secret_slice(Personality::AuthenticatedUnlock).is_none());
}

#[test]
fn set_personality_stub_is_fail_closed() {
    use crate::{set_personality_stub, Personality, UnlockCapability};
    use galdr_core::GaldrError;

    let err = set_personality_stub(Personality::MassStorageDecoy, None);
    assert_eq!(err, Err(GaldrError::PrivilegedOperationDenied));
    assert!(err.unwrap_err().is_permanent_denial());

    let err = set_personality_stub(
        Personality::AuthenticatedUnlock,
        Some(UnlockCapability(1)),
    );
    assert_eq!(err, Err(GaldrError::PrivilegedOperationDenied));
}
