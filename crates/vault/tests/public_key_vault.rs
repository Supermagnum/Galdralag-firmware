//! Integration: public keys can be added, read back, and removed from vault storage.

use galdr_core::fake_hal::FakeVaultStorage;
use vault::{
    vault_delete_public_key, vault_load_public_key_der, vault_store_public_key_der, PublicKeySlot,
    PublicKeyVaultError,
};

#[test]
fn public_key_add_load_delete_on_device() {
    let mut mem = FakeVaultStorage::new(65536);
    let slot = PublicKeySlot(2);
    let der = b"0\x82\x01\x00 pretend-spki-der-for-test".as_slice();

    vault_store_public_key_der(&mut mem, &slot, der, true).expect("store");
    let loaded = vault_load_public_key_der(&mem, &slot).expect("load");
    assert_eq!(loaded.as_slice(), der);

    vault_delete_public_key(&mut mem, &slot).expect("delete");
    assert_eq!(
        vault_load_public_key_der(&mem, &slot),
        Err(PublicKeyVaultError::SlotEmpty)
    );

    vault_store_public_key_der(&mut mem, &slot, b"replacement-key", true).expect("re-store");
    assert_eq!(
        vault_load_public_key_der(&mem, &slot).unwrap().as_slice(),
        b"replacement-key"
    );
}
