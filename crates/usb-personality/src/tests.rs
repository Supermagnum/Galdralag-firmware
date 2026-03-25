use crate::{usb_exposed_secret_slice, Personality};

#[test]
fn uninformed_mass_storage_reveals_no_secret_bytes() {
    assert!(usb_exposed_secret_slice(Personality::MassStorageDecoy).is_none());
}

#[test]
fn authenticated_path_still_hides_raw_keys_in_scaffold() {
    assert!(usb_exposed_secret_slice(Personality::AuthenticatedUnlock).is_none());
}
