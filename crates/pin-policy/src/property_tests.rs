use crate::machine::pin_compare;
use proptest::prelude::*;

proptest! {
    #[test]
    fn pin_compare_reflexive_equal(x in prop::collection::vec(any::<u8>(), 0..32)) {
        assert!(bool::from(pin_compare(&x, &x)));
    }
}
