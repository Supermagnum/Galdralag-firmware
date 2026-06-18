//! Invariants: HKDF labels, key-type layout, ephemeral handling, Shamir share hygiene (scaffold).

use crate::kdf_policy::KeyPurpose;
use crate::key_material::{EphemeralEcdhSecretMaterial, VaultKey256};
use crate::session::VaultSessionState;
use crate::GaldrError;
use hkdf::Hkdf;
use proptest::prelude::*;
use sha2::Sha512;
use static_assertions::{assert_not_impl_all, assert_impl_all};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

assert_not_impl_all!(VaultKey256: Clone, Copy);
assert_not_impl_all!(EphemeralEcdhSecretMaterial: Clone, Copy);
assert_impl_all!(VaultKey256: Zeroize);

#[test]
fn all_key_purposes_have_distinct_hkdf_info() {
    let purposes = [
        KeyPurpose::VaultRootUnwrap,
        KeyPurpose::RramBlobWrap,
        KeyPurpose::StorageSeal,
        KeyPurpose::UsbSession,
        KeyPurpose::PinVerifier,
        KeyPurpose::OpenPgpSigning,
        KeyPurpose::KeyAgreement,
        KeyPurpose::ShamirRecovery,
    ];
    for i in 0..purposes.len() {
        for j in i + 1..purposes.len() {
            assert_ne!(purposes[i].info(), purposes[j].info());
        }
    }
}

proptest! {
    #[test]
    fn hkdf_info_never_empty(_ in any::<u32>()) {
        for p in [
            KeyPurpose::VaultRootUnwrap,
            KeyPurpose::RramBlobWrap,
            KeyPurpose::StorageSeal,
            KeyPurpose::UsbSession,
            KeyPurpose::PinVerifier,
            KeyPurpose::OpenPgpSigning,
            KeyPurpose::KeyAgreement,
            KeyPurpose::ShamirRecovery,
        ] {
            prop_assert!(!p.info().is_empty());
        }
    }
}

#[test]
fn hkdf_sha512_uses_explicit_info_per_purpose() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let hk = Hkdf::<Sha512>::new(Some(b"salt"), b"ikm");
    hk.expand(KeyPurpose::UsbSession.info(), &mut a).unwrap();
    hk.expand(KeyPurpose::PinVerifier.info(), &mut b).unwrap();
    assert_ne!(a, b);
}

#[test]
fn derive_stub_returns_not_implemented() {
    let mut out = [0u8; 32];
    let r = crate::derive_subkey_sha512_stub(b"k", b"s", KeyPurpose::VaultRootUnwrap, &mut out);
    assert_eq!(r, Err(GaldrError::NotImplemented));
}

#[test]
fn ephemeral_material_dropped_after_derive_simulation() {
    let mut st = VaultSessionState::EphemeralPending;
    let _secret = EphemeralEcdhSecretMaterial::new_zeroed();
    drop(_secret);
    st = VaultSessionState::SessionActive;
    assert_eq!(st, VaultSessionState::SessionActive);
}

#[test]
fn shamir_share_buffers_zeroised_after_reconstruct_todo() {
    let mut share_a = [9u8; 32];
    let mut share_b = [7u8; 32];
    share_a.zeroize();
    share_b.zeroize();
    assert!(bool::from(
        share_a
            .as_slice()
            .ct_eq(&[0u8; 32])
    ));
    assert!(bool::from(
        share_b
            .as_slice()
            .ct_eq(&[0u8; 32])
    ));
}
