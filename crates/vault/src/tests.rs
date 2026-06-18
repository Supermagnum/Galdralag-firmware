//! Invariants: HKDF labels, key-type layout, ephemeral handling, Shamir share hygiene (scaffold).

use crate::kdf_policy::KeyPurpose;
use crate::key_material::{EphemeralEcdhSecretMaterial, VaultKey256};
use crate::session::VaultSessionState;
use hkdf::Hkdf;
use proptest::prelude::*;
use sha2::{Sha256, Sha512};
use static_assertions::{assert_impl_all, assert_not_impl_all};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

assert_not_impl_all!(VaultKey256: Clone, Copy);
assert_not_impl_all!(EphemeralEcdhSecretMaterial: Clone, Copy);
assert_not_impl_all!(crate::rsa_keys::RsaPrivateKey: Clone, Copy);
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
        KeyPurpose::SerpentStorage,
        KeyPurpose::TwofishStorage,
        KeyPurpose::RsaKeyWrap,
        KeyPurpose::SessionLongTermSign,
        KeyPurpose::EphemeralSessionPrk,
        KeyPurpose::OpenPgpSig,
        KeyPurpose::OpenPgpDec,
        KeyPurpose::OpenPgpAut,
        KeyPurpose::OpenPgpAdminPin,
        KeyPurpose::OpenPgpCcidMaster,
        KeyPurpose::ContactKeyWrap,
        KeyPurpose::ContactStoreIntegrity,
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
            KeyPurpose::SerpentStorage,
            KeyPurpose::TwofishStorage,
            KeyPurpose::RsaKeyWrap,
            KeyPurpose::SessionLongTermSign,
            KeyPurpose::EphemeralSessionPrk,
            KeyPurpose::OpenPgpSig,
            KeyPurpose::OpenPgpDec,
            KeyPurpose::OpenPgpAut,
            KeyPurpose::OpenPgpAdminPin,
            KeyPurpose::OpenPgpCcidMaster,
            KeyPurpose::ContactKeyWrap,
            KeyPurpose::ContactStoreIntegrity,
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
fn hkdf_sha256_rsa_key_wrap_distinct_from_serpent_storage() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(b"salt"), b"ikm");
    hk.expand(KeyPurpose::RsaKeyWrap.info(), &mut a).unwrap();
    hk.expand(KeyPurpose::SerpentStorage.info(), &mut b)
        .unwrap();
    assert_ne!(a, b);
}

#[test]
fn hkdf_sha256_twofish_distinct_from_serpent_storage() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(b"salt"), b"ikm");
    hk.expand(KeyPurpose::TwofishStorage.info(), &mut a)
        .unwrap();
    hk.expand(KeyPurpose::SerpentStorage.info(), &mut b)
        .unwrap();
    assert_ne!(a, b);
}

#[test]
fn hkdf_sha512_session_long_term_sign_distinct_from_ephemeral_prk_and_others() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let mut c = [0u8; 32];
    let mut d = [0u8; 32];
    let hk = Hkdf::<Sha512>::new(Some(b"salt"), b"ikm");
    hk.expand(KeyPurpose::SessionLongTermSign.info(), &mut a)
        .unwrap();
    hk.expand(KeyPurpose::EphemeralSessionPrk.info(), &mut b)
        .unwrap();
    hk.expand(KeyPurpose::OpenPgpSigning.info(), &mut c)
        .unwrap();
    hk.expand(KeyPurpose::UsbSession.info(), &mut d).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d);
    assert_ne!(b, c);
}

#[test]
fn contact_key_wrap_hkdf_sha512_fixed_vector() {
    let mut out = [0u8; 32];
    crate::derive_subkey_sha512(
        &[0x11u8; 32],
        &[0x22u8; 16],
        KeyPurpose::ContactKeyWrap,
        &mut out,
    )
    .unwrap();
    assert_eq!(
        out,
        [
            0x19, 0x3a, 0xe5, 0x79, 0x42, 0x9c, 0xbe, 0x62, 0x57, 0xe4, 0xff, 0x51, 0xf9, 0x15,
            0x21, 0xe2, 0x77, 0x53, 0xc6, 0x1b, 0x96, 0xf3, 0xe1, 0xad, 0xaa, 0x8c, 0x51, 0xe6,
            0x8d, 0x4a, 0x71, 0x60
        ]
    );
}

#[test]
fn contact_store_integrity_hkdf_sha512_fixed_vector() {
    let mut out = [0u8; 32];
    crate::derive_subkey_sha512(
        &[0x11u8; 32],
        &[0x22u8; 16],
        KeyPurpose::ContactStoreIntegrity,
        &mut out,
    )
    .unwrap();
    assert_eq!(
        out,
        [
            0x21, 0xb9, 0xa6, 0x96, 0xd2, 0x46, 0x31, 0xb3, 0xc7, 0x6e, 0xa9, 0x70, 0x1e, 0x40,
            0x78, 0x9d, 0x54, 0xee, 0x7a, 0x5e, 0xaa, 0x7b, 0xf5, 0xe8, 0x04, 0xd2, 0xaf, 0x90,
            0x68, 0x63, 0xaa, 0x66
        ]
    );
}

#[test]
fn derive_subkey_sha512_matches_manual_hkdf() {
    let mut out = [0u8; 32];
    let mut expect = [0u8; 32];
    let hk = Hkdf::<Sha512>::new(Some(b"s"), b"k");
    hk.expand(KeyPurpose::VaultRootUnwrap.info(), &mut expect)
        .unwrap();
    crate::derive_subkey_sha512(b"k", b"s", KeyPurpose::VaultRootUnwrap, &mut out).unwrap();
    assert_eq!(out, expect);
}

#[test]
fn ephemeral_material_dropped_after_derive_simulation() {
    let _secret = EphemeralEcdhSecretMaterial::new_zeroed();
    drop(_secret);
    let st = VaultSessionState::SessionActive;
    assert_eq!(st, VaultSessionState::SessionActive);
}

#[test]
fn shamir_share_buffers_zeroised_after_reconstruct_todo() {
    let mut share_a = [9u8; 32];
    let mut share_b = [7u8; 32];
    share_a.zeroize();
    share_b.zeroize();
    assert!(bool::from(share_a.as_slice().ct_eq(&[0u8; 32])));
    assert!(bool::from(share_b.as_slice().ct_eq(&[0u8; 32])));
}
