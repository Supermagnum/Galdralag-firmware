use crate::sha256_manifest_chunk;
use proptest::prelude::*;

proptest! {
    #[test]
    fn sha256_deterministic(x in prop::collection::vec(any::<u8>(), 0..64)) {
        let a = sha256_manifest_chunk(&x);
        let b = sha256_manifest_chunk(&x);
        assert_eq!(a, b);
    }
}
