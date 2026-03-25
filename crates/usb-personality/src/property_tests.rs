use crate::{usb_exposed_secret_slice, Personality};
use proptest::prelude::*;

proptest! {
    #[test]
    fn mass_storage_never_exposes_slice(_ in any::<u64>()) {
        assert!(usb_exposed_secret_slice(Personality::MassStorageDecoy).is_none());
    }
}
