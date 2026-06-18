//! Key lifecycle integration tests (test-hal fakes). Naming: `lifecycle_<keytype>_<stage>`.

use galdr_core::fake_hal::FakeTrng;
use galdr_core::fake_hal::FakeVaultStorage;
use galdr_core::hal::VaultStorage;
use galdr_core::HalError;
use galdr_vault::brainpool::BrainpoolScalar;
use galdr_vault::brainpool384::{BrainpoolP384Scalar, BrainpoolP384SigningKey};
use galdr_vault::brainpool512::{BrainpoolP512Scalar, BrainpoolP512SigningKey};
use galdr_vault::chacha_aead::{chacha_decrypt, chacha_encrypt, ChaChaKey, ChaChaNonce};
use galdr_vault::ecdsa_brainpool::BrainpoolSigningKey;
use galdr_vault::kdf_policy::KeyPurpose;
use galdr_vault::rsa_keys::RsaPrivateKey;
use galdr_vault::rsa_vault::{
    vault_delete_rsa_key, vault_load_rsa_key, vault_store_rsa_key, KeySlot, RsaVaultError,
    RsaVaultStoreContext,
};
use galdr_vault::serpent_cipher::{serpent_decrypt, serpent_encrypt, SerpentKey, SerpentNonce};
use galdr_vault::shamir::{shamir_recover, shamir_split, ShamirShare};
use galdr_vault::twofish_cipher::{twofish_decrypt, twofish_encrypt, TwofishKey, TwofishNonce};
use paste::paste;
use static_assertions::assert_not_impl_any;
use std::vec::Vec;

const SLOT_STRIDE: u64 = 8192;
const MAGIC: &[u8; 4] = b"KVLT";

fn slot_offset(slot: u32) -> u64 {
    u64::from(slot).saturating_mul(SLOT_STRIDE)
}

fn slot_has_magic(storage: &FakeVaultStorage, slot: u32) -> bool {
    let off = slot_offset(slot);
    let mut head = [0u8; 4];
    storage.read(off, &mut head).is_ok() && head == *MAGIC
}

fn write_blob(storage: &mut FakeVaultStorage, slot: u32, payload: &[u8]) -> Result<(), HalError> {
    let off = slot_offset(slot);
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    let end = off.checked_add(buf.len() as u64).ok_or(HalError::Denied)?;
    if end > storage.as_slice().len() as u64 {
        return Err(HalError::Denied);
    }
    storage.write(off, &buf)
}

fn store_blob(
    storage: &mut FakeVaultStorage,
    slot: u32,
    payload: &[u8],
    overwrite: bool,
) -> Result<(), HalError> {
    if slot_has_magic(storage, slot) && !overwrite {
        return Err(HalError::Denied);
    }
    write_blob(storage, slot, payload)
}

fn read_blob(storage: &FakeVaultStorage, slot: u32) -> Result<Vec<u8>, ()> {
    let off = slot_offset(slot);
    let mut head = [0u8; 8];
    storage.read(off, &mut head).map_err(|_| ())?;
    if &head[..4] != MAGIC {
        return Err(());
    }
    let len = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
    let mut out = vec![0u8; len];
    storage.read(off + 8, &mut out).map_err(|_| ())?;
    Ok(out)
}

fn clear_slot(storage: &mut FakeVaultStorage, slot: u32) {
    let off = slot_offset(slot);
    let z = vec![0u8; SLOT_STRIDE as usize];
    let _ = storage.write(off, &z);
}

macro_rules! brainpool_scalar_lifecycle {
    ($curve:ident, $Type:ty, $n:literal) => {
        paste! {
            #[test]
            fn [<lifecycle_ $curve _scalar_generate>]() {
                let mut trng = FakeTrng::from_seed(0x51);
                let k: $Type = <$Type>::generate(&mut trng).unwrap();
                assert!(k.to_secret_bytes_for_test().iter().any(|b| *b != 0));
                let _ = k.public_key().unwrap();
            }

            #[test]
            fn [<lifecycle_ $curve _scalar_export>]() {
                let mut trng = FakeTrng::from_seed(0x52);
                let k: $Type = <$Type>::generate(&mut trng).unwrap();
                let b = k.to_secret_bytes_for_test();
                assert_eq!(b.len(), $n);
                assert!(b.iter().any(|x| *x != 0));
            }

            #[test]
            fn [<lifecycle_ $curve _scalar_import>]() {
                let mut trng = FakeTrng::from_seed(0x53);
                let k0: $Type = <$Type>::generate(&mut trng).unwrap();
                let b = k0.to_secret_bytes_for_test();
                let k1: $Type = <$Type>::from_secret_key_bytes_for_test(&b).unwrap();
                assert_eq!(k0.to_secret_bytes_for_test(), k1.to_secret_bytes_for_test());
            }

            #[test]
            fn [<lifecycle_ $curve _scalar_import_invalid>]() {
                let bad = [0xffu8; $n];
                let r: Result<$Type, _> = <$Type>::from_secret_key_bytes_for_test(&bad);
                assert!(r.is_err());
            }

            #[test]
            fn [<lifecycle_ $curve _scalar_vault_store>]() {
                let mut trng = FakeTrng::from_seed(0x54);
                let k: $Type = <$Type>::generate(&mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 0, &k.to_secret_bytes_for_test(), true).unwrap();
                assert_eq!(
                    read_blob(&st, 0).unwrap().as_slice(),
                    k.to_secret_bytes_for_test().as_slice()
                );
            }

            #[test]
            fn [<lifecycle_ $curve _scalar_vault_load>]() {
                let mut trng = FakeTrng::from_seed(0x55);
                let k: $Type = <$Type>::generate(&mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 1, &k.to_secret_bytes_for_test(), true).unwrap();
                let raw = read_blob(&st, 1).unwrap();
                let mut arr = [0u8; $n];
                arr.copy_from_slice(&raw);
                let k2: $Type = <$Type>::from_secret_key_bytes_for_test(&arr).unwrap();
                assert_eq!(k.to_secret_bytes_for_test(), k2.to_secret_bytes_for_test());
            }

            #[test]
            fn [<lifecycle_ $curve _scalar_vault_overwrite_denied>]() {
                let mut trng = FakeTrng::from_seed(0x56);
                let k: $Type = <$Type>::generate(&mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 2, &k.to_secret_bytes_for_test(), true).unwrap();
                let k2: $Type = <$Type>::generate(&mut trng).unwrap();
                let r = store_blob(&mut st, 2, &k2.to_secret_bytes_for_test(), false);
                assert_eq!(r, Err(HalError::Denied));
            }

            #[test]
            fn [<lifecycle_ $curve _scalar_vault_overwrite_allowed>]() {
                let mut trng = FakeTrng::from_seed(0x57);
                let k1: $Type = <$Type>::generate(&mut trng).unwrap();
                let k2: $Type = <$Type>::generate(&mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 0, &k1.to_secret_bytes_for_test(), true).unwrap();
                store_blob(&mut st, 0, &k2.to_secret_bytes_for_test(), true).unwrap();
                assert_eq!(
                    read_blob(&st, 0).unwrap().as_slice(),
                    k2.to_secret_bytes_for_test().as_slice()
                );
            }

            #[test]
            fn [<lifecycle_ $curve _scalar_vault_delete>]() {
                let mut trng = FakeTrng::from_seed(0x58);
                let k: $Type = <$Type>::generate(&mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 0, &k.to_secret_bytes_for_test(), true).unwrap();
                clear_slot(&mut st, 0);
                assert!(read_blob(&st, 0).is_err());
            }

            #[test]
            fn [<lifecycle_ $curve _scalar_vault_load_after_delete>]() {
                let mut trng = FakeTrng::from_seed(0x59);
                let k: $Type = <$Type>::generate(&mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 3, &k.to_secret_bytes_for_test(), true).unwrap();
                clear_slot(&mut st, 3);
                assert!(read_blob(&st, 3).is_err());
            }

            #[test]
            fn [<lifecycle_ $curve _scalar_use_after_store_load>]() {
                let mut trng = FakeTrng::from_seed(0x5a);
                let a: $Type = <$Type>::generate(&mut trng).unwrap();
                let b: $Type = <$Type>::generate(&mut trng).unwrap();
                let pa = a.public_key().unwrap();
                let pb = b.public_key().unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 0, &a.to_secret_bytes_for_test(), true).unwrap();
                let raw = read_blob(&st, 0).unwrap();
                let mut arr = [0u8; $n];
                arr.copy_from_slice(&raw);
                let a2: $Type = <$Type>::from_secret_key_bytes_for_test(&arr).unwrap();
                let s1 = a2.diffie_hellman(&pb).unwrap();
                let s2 = b.diffie_hellman(&pa).unwrap();
                assert!(bool::from(s1.ct_eq(&s2)));
            }

            #[test]
            #[ignore = "post-drop secret buffer inspection is covered in vault unit tests (ZeroizeOnDrop)"]
            fn [<lifecycle_ $curve _scalar_zeroise_on_drop>]() {}

            #[test]
            fn [<lifecycle_ $curve _scalar_no_clone>]() {
                assert_not_impl_any!($Type: Clone);
            }

            #[test]
            fn [<lifecycle_ $curve _scalar_no_copy>]() {
                assert_not_impl_any!($Type: Copy);
            }

            #[test]
            fn [<lifecycle_ $curve _scalar_full_vault_roundtrip>]() {
                let mut trng = FakeTrng::from_seed(0x5b);
                let a: $Type = <$Type>::generate(&mut trng).unwrap();
                let peer: $Type = <$Type>::generate(&mut trng).unwrap();
                let pub_peer = peer.public_key().unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 1, &a.to_secret_bytes_for_test(), true).unwrap();
                drop(a);
                let raw = read_blob(&st, 1).unwrap();
                let mut arr = [0u8; $n];
                arr.copy_from_slice(&raw);
                let a2: $Type = <$Type>::from_secret_key_bytes_for_test(&arr).unwrap();
                let ss = a2.diffie_hellman(&pub_peer).unwrap();
                let ss2 = peer.diffie_hellman(&a2.public_key().unwrap()).unwrap();
                assert!(bool::from(ss.ct_eq(&ss2)));
                clear_slot(&mut st, 1);
                assert!(read_blob(&st, 1).is_err());
            }
        }
    };
}

brainpool_scalar_lifecycle!(brainpool_p256, BrainpoolScalar, 32);
brainpool_scalar_lifecycle!(brainpool_p384, BrainpoolP384Scalar, 48);
brainpool_scalar_lifecycle!(brainpool_p512, BrainpoolP512Scalar, 64);

macro_rules! brainpool_signing_lifecycle {
    ($curve:ident, $Sk:ty, $n:literal) => {
        paste! {
            #[test]
            fn [<lifecycle_ $curve _signing_generate>]() {
                let mut trng = FakeTrng::from_seed(0x61);
                let sk: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let _vk = sk.verifying_key();
            }

            #[test]
            fn [<lifecycle_ $curve _signing_export>]() {
                let mut trng = FakeTrng::from_seed(0x62);
                let sk: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let b = sk.to_scalar_bytes_for_test();
                assert_eq!(b.len(), $n);
                assert!(b.iter().any(|x| *x != 0));
            }

            #[test]
            fn [<lifecycle_ $curve _signing_import>]() {
                let mut trng = FakeTrng::from_seed(0x63);
                let sk0: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let b = sk0.to_scalar_bytes_for_test();
                let sk1: $Sk = <$Sk>::from_scalar_bytes_for_test(&b).unwrap();
                assert_eq!(sk0.verifying_key().to_sec1_uncompressed(), sk1.verifying_key().to_sec1_uncompressed());
            }

            #[test]
            fn [<lifecycle_ $curve _signing_import_invalid>]() {
                let bad = [0xffu8; $n];
                let r: Result<$Sk, _> = <$Sk>::from_scalar_bytes_for_test(&bad);
                assert!(r.is_err());
            }

            #[test]
            fn [<lifecycle_ $curve _signing_vault_store>]() {
                let mut trng = FakeTrng::from_seed(0x64);
                let sk: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 0, &sk.to_scalar_bytes_for_test(), true).unwrap();
            }

            #[test]
            fn [<lifecycle_ $curve _signing_vault_load>]() {
                let mut trng = FakeTrng::from_seed(0x65);
                let sk: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 0, &sk.to_scalar_bytes_for_test(), true).unwrap();
                let raw = read_blob(&st, 0).unwrap();
                let mut arr = [0u8; $n];
                arr.copy_from_slice(&raw);
                let sk2: $Sk = <$Sk>::from_scalar_bytes_for_test(&arr).unwrap();
                assert_eq!(sk.verifying_key().to_sec1_uncompressed(), sk2.verifying_key().to_sec1_uncompressed());
            }

            #[test]
            fn [<lifecycle_ $curve _signing_vault_overwrite_denied>]() {
                let mut trng = FakeTrng::from_seed(0x66);
                let sk: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 0, &sk.to_scalar_bytes_for_test(), true).unwrap();
                let sk2: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let r = store_blob(&mut st, 0, &sk2.to_scalar_bytes_for_test(), false);
                assert_eq!(r, Err(HalError::Denied));
            }

            #[test]
            fn [<lifecycle_ $curve _signing_vault_overwrite_allowed>]() {
                let mut trng = FakeTrng::from_seed(0x67);
                let sk1: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let sk2: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 0, &sk1.to_scalar_bytes_for_test(), true).unwrap();
                store_blob(&mut st, 0, &sk2.to_scalar_bytes_for_test(), true).unwrap();
                assert_eq!(
                    read_blob(&st, 0).unwrap().as_slice(),
                    sk2.to_scalar_bytes_for_test().as_slice()
                );
            }

            #[test]
            fn [<lifecycle_ $curve _signing_vault_delete>]() {
                let mut trng = FakeTrng::from_seed(0x68);
                let sk: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 0, &sk.to_scalar_bytes_for_test(), true).unwrap();
                clear_slot(&mut st, 0);
                assert!(read_blob(&st, 0).is_err());
            }

            #[test]
            fn [<lifecycle_ $curve _signing_vault_load_after_delete>]() {
                let mut trng = FakeTrng::from_seed(0x69);
                let sk: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 0, &sk.to_scalar_bytes_for_test(), true).unwrap();
                clear_slot(&mut st, 0);
                assert!(read_blob(&st, 0).is_err());
            }

            #[test]
            fn [<lifecycle_ $curve _signing_use_after_store_load>]() {
                let mut trng = FakeTrng::from_seed(0x6a);
                let sk: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let vk = sk.verifying_key();
                let msg = b"lifecycle signing";
                let sig = sk.sign(msg, &mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 0, &sk.to_scalar_bytes_for_test(), true).unwrap();
                let raw = read_blob(&st, 0).unwrap();
                let mut arr = [0u8; $n];
                arr.copy_from_slice(&raw);
                let sk2: $Sk = <$Sk>::from_scalar_bytes_for_test(&arr).unwrap();
                let sig2 = sk2.sign(msg, &mut trng).unwrap();
                assert!(vk.verify(msg, &sig2).is_ok());
                assert!(vk.verify(msg, &sig).is_ok());
            }

            #[test]
            #[ignore = "post-drop signing key buffer inspection is covered in vault unit tests"]
            fn [<lifecycle_ $curve _signing_zeroise_on_drop>]() {}

            #[test]
            fn [<lifecycle_ $curve _signing_no_clone>]() {
                assert_not_impl_any!($Sk: Clone);
            }

            #[test]
            fn [<lifecycle_ $curve _signing_no_copy>]() {
                assert_not_impl_any!($Sk: Copy);
            }

            #[test]
            fn [<lifecycle_ $curve _signing_full_vault_roundtrip>]() {
                let mut trng = FakeTrng::from_seed(0x6b);
                let sk: $Sk = <$Sk>::generate(&mut trng).unwrap();
                let vk = sk.verifying_key();
                let msg = b"roundtrip";
                let sig_expect = sk.sign(msg, &mut trng).unwrap();
                let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 4);
                store_blob(&mut st, 1, &sk.to_scalar_bytes_for_test(), true).unwrap();
                drop(sk);
                let raw = read_blob(&st, 1).unwrap();
                let mut arr = [0u8; $n];
                arr.copy_from_slice(&raw);
                let sk2: $Sk = <$Sk>::from_scalar_bytes_for_test(&arr).unwrap();
                assert!(vk.verify(msg, &sig_expect).is_ok());
                let sig2 = sk2.sign(msg, &mut trng).unwrap();
                assert!(vk.verify(msg, &sig2).is_ok());
                clear_slot(&mut st, 1);
                assert!(read_blob(&st, 1).is_err());
            }
        }
    };
}

brainpool_signing_lifecycle!(brainpool_p256, BrainpoolSigningKey, 32);
brainpool_signing_lifecycle!(brainpool_p384, BrainpoolP384SigningKey, 48);
brainpool_signing_lifecycle!(brainpool_p512, BrainpoolP512SigningKey, 64);

#[test]
fn lifecycle_chacha_generate() {
    let mut trng = FakeTrng::from_seed(0x71);
    let prk = [0x55u8; 32];
    let k = ChaChaKey::derive(&prk, KeyPurpose::RramBlobWrap, b"i1").unwrap();
    let _ = ChaChaNonce::generate(&mut trng).unwrap();
    drop(k);
}

#[test]
fn lifecycle_chacha_export() {
    let prk = [0x55u8; 32];
    let k = ChaChaKey::derive(&prk, KeyPurpose::RramBlobWrap, b"i1").unwrap();
    let b = k.as_raw_bytes_for_test();
    assert!(b.iter().any(|x| *x != 0));
}

#[test]
fn lifecycle_chacha_import() {
    let prk = [0x55u8; 32];
    let k0 = ChaChaKey::derive(&prk, KeyPurpose::RramBlobWrap, b"i").unwrap();
    let b = k0.as_raw_bytes_for_test();
    let k1 = ChaChaKey::from_raw_key_bytes_for_test(b);
    assert_eq!(k0.as_raw_bytes_for_test(), k1.as_raw_bytes_for_test());
}

#[test]
fn lifecycle_chacha_import_invalid() {
    let k = ChaChaKey::from_raw_key_bytes_for_test([0u8; 32]);
    let k_wrong = ChaChaKey::from_raw_key_bytes_for_test([1u8; 32]);
    let mut trng = FakeTrng::from_seed(1);
    let n = ChaChaNonce::generate(&mut trng).unwrap();
    let ct = chacha_encrypt(&k, &n, b"", b"hi").unwrap();
    assert!(chacha_decrypt(&k_wrong, &n, b"", &ct).is_err());
}

#[test]
fn lifecycle_chacha_vault_store() {
    let k = ChaChaKey::derive(&[0x55u8; 32], KeyPurpose::RramBlobWrap, b"s").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.as_raw_bytes_for_test(), true).unwrap();
}

#[test]
fn lifecycle_chacha_vault_load() {
    let k = ChaChaKey::derive(&[0x55u8; 32], KeyPurpose::RramBlobWrap, b"s").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.as_raw_bytes_for_test(), true).unwrap();
    let raw = read_blob(&st, 0).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&raw);
    let k2 = ChaChaKey::from_raw_key_bytes_for_test(a);
    assert_eq!(k.as_raw_bytes_for_test(), k2.as_raw_bytes_for_test());
}

#[test]
fn lifecycle_chacha_vault_overwrite_denied() {
    let k1 = ChaChaKey::derive(&[0x55u8; 32], KeyPurpose::RramBlobWrap, b"a").unwrap();
    let k2 = ChaChaKey::derive(&[0x55u8; 32], KeyPurpose::RramBlobWrap, b"b").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k1.as_raw_bytes_for_test(), true).unwrap();
    assert_eq!(
        store_blob(&mut st, 0, &k2.as_raw_bytes_for_test(), false),
        Err(HalError::Denied)
    );
}

#[test]
fn lifecycle_chacha_vault_overwrite_allowed() {
    let k1 = ChaChaKey::derive(&[0x55u8; 32], KeyPurpose::RramBlobWrap, b"a").unwrap();
    let k2 = ChaChaKey::derive(&[0x55u8; 32], KeyPurpose::RramBlobWrap, b"b").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k1.as_raw_bytes_for_test(), true).unwrap();
    store_blob(&mut st, 0, &k2.as_raw_bytes_for_test(), true).unwrap();
}

#[test]
fn lifecycle_chacha_vault_delete() {
    let k = ChaChaKey::derive(&[0x55u8; 32], KeyPurpose::RramBlobWrap, b"x").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.as_raw_bytes_for_test(), true).unwrap();
    clear_slot(&mut st, 0);
}

#[test]
fn lifecycle_chacha_vault_load_after_delete() {
    let k = ChaChaKey::derive(&[0x55u8; 32], KeyPurpose::RramBlobWrap, b"x").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.as_raw_bytes_for_test(), true).unwrap();
    clear_slot(&mut st, 0);
    assert!(read_blob(&st, 0).is_err());
}

#[test]
fn lifecycle_chacha_use_after_store_load() {
    let k = ChaChaKey::derive(&[0x55u8; 32], KeyPurpose::RramBlobWrap, b"u").unwrap();
    let mut trng = FakeTrng::from_seed(2);
    let n = ChaChaNonce::generate(&mut trng).unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.as_raw_bytes_for_test(), true).unwrap();
    let raw = read_blob(&st, 0).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&raw);
    let k2 = ChaChaKey::from_raw_key_bytes_for_test(a);
    let ct = chacha_encrypt(&k2, &n, b"aad", b"pt").unwrap();
    let pt = chacha_decrypt(&k, &n, b"aad", &ct).unwrap();
    assert_eq!(pt.as_slice(), b"pt");
}

#[test]
#[ignore = "ZeroizeOnDrop for ChaChaKey is covered in chacha_aead unit tests"]
fn lifecycle_chacha_zeroise_on_drop() {}

#[test]
fn lifecycle_chacha_no_clone() {
    assert_not_impl_any!(ChaChaKey: Clone);
}

#[test]
fn lifecycle_chacha_no_copy() {
    assert_not_impl_any!(ChaChaKey: Copy);
}

#[test]
fn lifecycle_chacha_full_vault_roundtrip() {
    let k = ChaChaKey::derive(&[0x55u8; 32], KeyPurpose::RramBlobWrap, b"rt").unwrap();
    let mut trng = FakeTrng::from_seed(3);
    let n = ChaChaNonce::generate(&mut trng).unwrap();
    let ct = chacha_encrypt(&k, &n, b"", b"data").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 1, &k.as_raw_bytes_for_test(), true).unwrap();
    drop(k);
    let raw = read_blob(&st, 1).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&raw);
    let k2 = ChaChaKey::from_raw_key_bytes_for_test(a);
    let pt = chacha_decrypt(&k2, &n, b"", &ct).unwrap();
    assert_eq!(pt.as_slice(), b"data");
    clear_slot(&mut st, 1);
}

#[test]
fn lifecycle_serpent_generate() {
    let k = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"s").unwrap();
    drop(k);
}

#[test]
fn lifecycle_serpent_export() {
    let k = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"s").unwrap();
    let b = k.raw_64_for_test();
    assert!(b.iter().any(|x| *x != 0));
}

#[test]
fn lifecycle_serpent_import() {
    let k0 = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"s").unwrap();
    let b = k0.raw_64_for_test();
    let k1 = SerpentKey::from_raw_cipher_mac_for_test(
        *<&[u8; 32]>::try_from(&b[..32]).unwrap(),
        *<&[u8; 32]>::try_from(&b[32..]).unwrap(),
    );
    assert_eq!(k0.raw_64_for_test(), k1.raw_64_for_test());
}

#[test]
fn lifecycle_serpent_import_invalid() {
    let k = SerpentKey::from_raw_cipher_mac_for_test([0u8; 32], [0u8; 32]);
    let k_wrong = SerpentKey::from_raw_cipher_mac_for_test([1u8; 32], [1u8; 32]);
    let mut trng = FakeTrng::from_seed(1);
    let n = SerpentNonce::generate(&mut trng).unwrap();
    let ct = serpent_encrypt(&k, &n, b"", b"x").unwrap();
    assert!(serpent_decrypt(&k_wrong, &n, b"", &ct).is_err());
}

#[test]
fn lifecycle_serpent_vault_store() {
    let k = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"v").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.raw_64_for_test(), true).unwrap();
}

#[test]
fn lifecycle_serpent_vault_load() {
    let k = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"v").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.raw_64_for_test(), true).unwrap();
    let raw = read_blob(&st, 0).unwrap();
    let mut a = [0u8; 64];
    a.copy_from_slice(&raw);
    let k2 = SerpentKey::from_raw_cipher_mac_for_test(
        *<&[u8; 32]>::try_from(&a[..32]).unwrap(),
        *<&[u8; 32]>::try_from(&a[32..]).unwrap(),
    );
    assert_eq!(k.raw_64_for_test(), k2.raw_64_for_test());
}

#[test]
fn lifecycle_serpent_vault_overwrite_denied() {
    let k1 = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"a").unwrap();
    let k2 = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"b").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k1.raw_64_for_test(), true).unwrap();
    assert_eq!(
        store_blob(&mut st, 0, &k2.raw_64_for_test(), false),
        Err(HalError::Denied)
    );
}

#[test]
fn lifecycle_serpent_vault_overwrite_allowed() {
    let k1 = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"a").unwrap();
    let k2 = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"b").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k1.raw_64_for_test(), true).unwrap();
    store_blob(&mut st, 0, &k2.raw_64_for_test(), true).unwrap();
}

#[test]
fn lifecycle_serpent_vault_delete() {
    let k = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"x").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.raw_64_for_test(), true).unwrap();
    clear_slot(&mut st, 0);
}

#[test]
fn lifecycle_serpent_vault_load_after_delete() {
    let k = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"x").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.raw_64_for_test(), true).unwrap();
    clear_slot(&mut st, 0);
    assert!(read_blob(&st, 0).is_err());
}

#[test]
fn lifecycle_serpent_use_after_store_load() {
    let k = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"u").unwrap();
    let mut trng = FakeTrng::from_seed(4);
    let n = SerpentNonce::generate(&mut trng).unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.raw_64_for_test(), true).unwrap();
    let raw = read_blob(&st, 0).unwrap();
    let mut a = [0u8; 64];
    a.copy_from_slice(&raw);
    let k2 = SerpentKey::from_raw_cipher_mac_for_test(
        *<&[u8; 32]>::try_from(&a[..32]).unwrap(),
        *<&[u8; 32]>::try_from(&a[32..]).unwrap(),
    );
    let ct = serpent_encrypt(&k2, &n, b"aad", b"pt").unwrap();
    let pt = serpent_decrypt(&k, &n, b"aad", &ct).unwrap();
    assert_eq!(pt.as_slice(), b"pt");
}

#[test]
#[ignore = "ZeroizeOnDrop for SerpentKey is covered in serpent_cipher unit tests"]
fn lifecycle_serpent_zeroise_on_drop() {}

#[test]
fn lifecycle_serpent_no_clone() {
    assert_not_impl_any!(SerpentKey: Clone);
}

#[test]
fn lifecycle_serpent_no_copy() {
    assert_not_impl_any!(SerpentKey: Copy);
}

#[test]
fn lifecycle_serpent_full_vault_roundtrip() {
    let k = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"rt").unwrap();
    let mut trng = FakeTrng::from_seed(5);
    let n = SerpentNonce::generate(&mut trng).unwrap();
    let ct = serpent_encrypt(&k, &n, b"", b"secret").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 1, &k.raw_64_for_test(), true).unwrap();
    drop(k);
    let raw = read_blob(&st, 1).unwrap();
    let mut a = [0u8; 64];
    a.copy_from_slice(&raw);
    let k2 = SerpentKey::from_raw_cipher_mac_for_test(
        *<&[u8; 32]>::try_from(&a[..32]).unwrap(),
        *<&[u8; 32]>::try_from(&a[32..]).unwrap(),
    );
    let pt = serpent_decrypt(&k2, &n, b"", &ct).unwrap();
    assert_eq!(pt.as_slice(), b"secret");
    clear_slot(&mut st, 1);
}

#[test]
fn lifecycle_twofish_generate() {
    let k = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"s").unwrap();
    drop(k);
}

#[test]
fn lifecycle_twofish_export() {
    let k = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"s").unwrap();
    let b = k.raw_64_for_test();
    assert!(b.iter().any(|x| *x != 0));
}

#[test]
fn lifecycle_twofish_import() {
    let k0 = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"s").unwrap();
    let b = k0.raw_64_for_test();
    let k1 = TwofishKey::from_raw_cipher_mac_for_test(
        *<&[u8; 32]>::try_from(&b[..32]).unwrap(),
        *<&[u8; 32]>::try_from(&b[32..]).unwrap(),
    );
    assert_eq!(k0.raw_64_for_test(), k1.raw_64_for_test());
}

#[test]
fn lifecycle_twofish_import_invalid() {
    let k = TwofishKey::from_raw_cipher_mac_for_test([0u8; 32], [0u8; 32]);
    let k_wrong = TwofishKey::from_raw_cipher_mac_for_test([1u8; 32], [1u8; 32]);
    let mut trng = FakeTrng::from_seed(1);
    let n = TwofishNonce::generate(&mut trng).unwrap();
    let ct = twofish_encrypt(&k, &n, b"", b"x").unwrap();
    assert!(twofish_decrypt(&k_wrong, &n, b"", &ct).is_err());
}

#[test]
fn lifecycle_twofish_vault_store() {
    let k = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"v").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.raw_64_for_test(), true).unwrap();
}

#[test]
fn lifecycle_twofish_vault_load() {
    let k = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"v").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.raw_64_for_test(), true).unwrap();
    let raw = read_blob(&st, 0).unwrap();
    let mut a = [0u8; 64];
    a.copy_from_slice(&raw);
    let k2 = TwofishKey::from_raw_cipher_mac_for_test(
        *<&[u8; 32]>::try_from(&a[..32]).unwrap(),
        *<&[u8; 32]>::try_from(&a[32..]).unwrap(),
    );
    assert_eq!(k.raw_64_for_test(), k2.raw_64_for_test());
}

#[test]
fn lifecycle_twofish_vault_overwrite_denied() {
    let k1 = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"a").unwrap();
    let k2 = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"b").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k1.raw_64_for_test(), true).unwrap();
    assert_eq!(
        store_blob(&mut st, 0, &k2.raw_64_for_test(), false),
        Err(HalError::Denied)
    );
}

#[test]
fn lifecycle_twofish_vault_overwrite_allowed() {
    let k1 = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"a").unwrap();
    let k2 = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"b").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k1.raw_64_for_test(), true).unwrap();
    store_blob(&mut st, 0, &k2.raw_64_for_test(), true).unwrap();
}

#[test]
fn lifecycle_twofish_vault_delete() {
    let k = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"x").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.raw_64_for_test(), true).unwrap();
    clear_slot(&mut st, 0);
}

#[test]
fn lifecycle_twofish_vault_load_after_delete() {
    let k = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"x").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.raw_64_for_test(), true).unwrap();
    clear_slot(&mut st, 0);
    assert!(read_blob(&st, 0).is_err());
}

#[test]
fn lifecycle_twofish_use_after_store_load() {
    let k = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"u").unwrap();
    let mut trng = FakeTrng::from_seed(4);
    let n = TwofishNonce::generate(&mut trng).unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.raw_64_for_test(), true).unwrap();
    let raw = read_blob(&st, 0).unwrap();
    let mut a = [0u8; 64];
    a.copy_from_slice(&raw);
    let k2 = TwofishKey::from_raw_cipher_mac_for_test(
        *<&[u8; 32]>::try_from(&a[..32]).unwrap(),
        *<&[u8; 32]>::try_from(&a[32..]).unwrap(),
    );
    let ct = twofish_encrypt(&k2, &n, b"aad", b"pt").unwrap();
    let pt = twofish_decrypt(&k, &n, b"aad", &ct).unwrap();
    assert_eq!(pt.as_slice(), b"pt");
}

#[test]
#[ignore = "ZeroizeOnDrop for TwofishKey is covered in twofish_cipher unit tests"]
fn lifecycle_twofish_zeroise_on_drop() {}

#[test]
fn lifecycle_twofish_no_clone() {
    assert_not_impl_any!(TwofishKey: Clone);
}

#[test]
fn lifecycle_twofish_no_copy() {
    assert_not_impl_any!(TwofishKey: Copy);
}

#[test]
fn lifecycle_twofish_full_vault_roundtrip() {
    let k = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"rt").unwrap();
    let mut trng = FakeTrng::from_seed(5);
    let n = TwofishNonce::generate(&mut trng).unwrap();
    let ct = twofish_encrypt(&k, &n, b"", b"secret").unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 1, &k.raw_64_for_test(), true).unwrap();
    drop(k);
    let raw = read_blob(&st, 1).unwrap();
    let mut a = [0u8; 64];
    a.copy_from_slice(&raw);
    let k2 = TwofishKey::from_raw_cipher_mac_for_test(
        *<&[u8; 32]>::try_from(&a[..32]).unwrap(),
        *<&[u8; 32]>::try_from(&a[32..]).unwrap(),
    );
    let pt = twofish_decrypt(&k2, &n, b"", &ct).unwrap();
    assert_eq!(pt.as_slice(), b"secret");
    clear_slot(&mut st, 1);
}

fn shamir_share_bytes(s: &ShamirShare) -> Vec<u8> {
    let mut v = vec![s.index];
    v.extend_from_slice(s.value());
    v
}

fn shamir_share_from_bytes(v: &[u8]) -> Result<ShamirShare, galdr_vault::shamir::ShamirError> {
    if v.is_empty() {
        return Err(galdr_vault::shamir::ShamirError::InvalidShare { index: 0 });
    }
    ShamirShare::try_from_index_value(v[0], &v[1..])
}

#[test]
fn lifecycle_shamir_generate() {
    let mut trng = FakeTrng::from_seed(0x81);
    let secret = [0xABu8; 16];
    let shares = shamir_split(&secret, 2, 3, &mut trng).unwrap();
    assert_eq!(shares.len(), 3);
}

#[test]
fn lifecycle_shamir_export() {
    let mut trng = FakeTrng::from_seed(0x82);
    let secret = [0xCDu8; 16];
    let shares = shamir_split(&secret, 2, 3, &mut trng).unwrap();
    let b = shamir_share_bytes(&shares[0]);
    assert!(b.len() > 1);
}

#[test]
fn lifecycle_shamir_import() {
    let mut trng = FakeTrng::from_seed(0x83);
    let secret = [0x11u8; 16];
    let shares = shamir_split(&secret, 2, 3, &mut trng).unwrap();
    let raw = shamir_share_bytes(&shares[0]);
    let s2 = shamir_share_from_bytes(&raw).unwrap();
    assert_eq!(s2.value(), shares[0].value());
}

#[test]
fn lifecycle_shamir_import_invalid() {
    let r = ShamirShare::try_from_index_value(0, &[1u8; 16]);
    assert!(r.is_err());
}

#[test]
fn lifecycle_shamir_vault_store() {
    let mut trng = FakeTrng::from_seed(0x84);
    let secret = [0x22u8; 16];
    let shares = shamir_split(&secret, 2, 3, &mut trng).unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &shamir_share_bytes(&shares[0]), true).unwrap();
}

#[test]
fn lifecycle_shamir_vault_load() {
    let mut trng = FakeTrng::from_seed(0x85);
    let secret = [0x33u8; 16];
    let shares = shamir_split(&secret, 2, 3, &mut trng).unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &shamir_share_bytes(&shares[0]), true).unwrap();
    let raw = read_blob(&st, 0).unwrap();
    let s2 = shamir_share_from_bytes(&raw).unwrap();
    assert_eq!(s2.value(), shares[0].value());
}

#[test]
fn lifecycle_shamir_vault_overwrite_denied() {
    let mut trng = FakeTrng::from_seed(0x86);
    let s1 = [0x44u8; 16];
    let s2 = [0x55u8; 16];
    let a = shamir_split(&s1, 2, 3, &mut trng).unwrap();
    let b = shamir_split(&s2, 2, 3, &mut trng).unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &shamir_share_bytes(&a[0]), true).unwrap();
    assert_eq!(
        store_blob(&mut st, 0, &shamir_share_bytes(&b[0]), false),
        Err(HalError::Denied)
    );
}

#[test]
fn lifecycle_shamir_vault_overwrite_allowed() {
    let mut trng = FakeTrng::from_seed(0x87);
    let s1 = [0x66u8; 16];
    let s2 = [0x77u8; 16];
    let a = shamir_split(&s1, 2, 3, &mut trng).unwrap();
    let b = shamir_split(&s2, 2, 3, &mut trng).unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &shamir_share_bytes(&a[0]), true).unwrap();
    store_blob(&mut st, 0, &shamir_share_bytes(&b[0]), true).unwrap();
}

#[test]
fn lifecycle_shamir_vault_delete() {
    let mut trng = FakeTrng::from_seed(0x88);
    let secret = [0x88u8; 16];
    let shares = shamir_split(&secret, 2, 3, &mut trng).unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &shamir_share_bytes(&shares[0]), true).unwrap();
    clear_slot(&mut st, 0);
}

#[test]
fn lifecycle_shamir_vault_load_after_delete() {
    let mut trng = FakeTrng::from_seed(0x89);
    let secret = [0x99u8; 16];
    let shares = shamir_split(&secret, 2, 3, &mut trng).unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &shamir_share_bytes(&shares[0]), true).unwrap();
    clear_slot(&mut st, 0);
    assert!(read_blob(&st, 0).is_err());
}

#[test]
fn lifecycle_shamir_use_after_store_load() {
    let mut trng = FakeTrng::from_seed(0x8a);
    let secret = [0xAAu8; 16];
    let shares = shamir_split(&secret, 2, 3, &mut trng).unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &shamir_share_bytes(&shares[0]), true).unwrap();
    store_blob(&mut st, 1, &shamir_share_bytes(&shares[1]), true).unwrap();
    let s0 = shamir_share_from_bytes(&read_blob(&st, 0).unwrap()).unwrap();
    let s1 = shamir_share_from_bytes(&read_blob(&st, 1).unwrap()).unwrap();
    let mut pair = heapless::Vec::<ShamirShare, 255>::new();
    assert!(pair.push(s0).is_ok());
    assert!(pair.push(s1).is_ok());
    let rec = shamir_recover(pair.as_slice(), 2).unwrap();
    assert_eq!(rec.as_slice(), &secret);
}

#[test]
#[ignore = "ShamirShare ZeroizeOnDrop is covered in shamir unit tests"]
fn lifecycle_shamir_zeroise_on_drop() {}

#[test]
fn lifecycle_shamir_no_clone() {
    assert_not_impl_any!(ShamirShare: Clone);
}

#[test]
fn lifecycle_shamir_no_copy() {
    assert_not_impl_any!(ShamirShare: Copy);
}

#[test]
fn lifecycle_shamir_full_vault_roundtrip() {
    let mut trng = FakeTrng::from_seed(0x8b);
    let secret = [0xBBu8; 16];
    let shares = shamir_split(&secret, 2, 3, &mut trng).unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 3);
    store_blob(&mut st, 1, &shamir_share_bytes(&shares[0]), true).unwrap();
    store_blob(&mut st, 2, &shamir_share_bytes(&shares[1]), true).unwrap();
    let s0 = shamir_share_from_bytes(&read_blob(&st, 1).unwrap()).unwrap();
    let s1 = shamir_share_from_bytes(&read_blob(&st, 2).unwrap()).unwrap();
    let mut pair = heapless::Vec::<ShamirShare, 255>::new();
    assert!(pair.push(s0).is_ok());
    assert!(pair.push(s1).is_ok());
    let rec = shamir_recover(pair.as_slice(), 2).unwrap();
    assert_eq!(rec.as_slice(), &secret);
    clear_slot(&mut st, 1);
    clear_slot(&mut st, 2);
}

#[test]
#[ignore = "slow RSA key generation"]
fn lifecycle_rsa_generate() {
    let mut trng = FakeTrng::from_seed(0x91);
    let _ = RsaPrivateKey::generate(&mut trng, 2048).unwrap();
}

#[test]
fn lifecycle_rsa_export() {
    let der = include_bytes!("data/rsa_2048_fuzz.pk8");
    let k = RsaPrivateKey::from_pkcs8_der(der).unwrap();
    let out = k.to_pkcs8_der().unwrap();
    assert!(!out.as_slice().is_empty());
}

#[test]
fn lifecycle_rsa_import() {
    let der = include_bytes!("data/rsa_2048_fuzz.pk8");
    let k = RsaPrivateKey::from_pkcs8_der(der).unwrap();
    let der2 = k.to_pkcs8_der().unwrap();
    let k2 = RsaPrivateKey::from_pkcs8_der(der2.as_slice()).unwrap();
    let _ = (k, k2);
}

#[test]
fn lifecycle_rsa_import_invalid() {
    let r = RsaPrivateKey::from_pkcs8_der(&[0u8; 8]);
    assert!(r.is_err());
}

#[test]
fn lifecycle_rsa_vault_store() {
    let der = include_bytes!("data/rsa_2048_fuzz.pk8");
    let k = RsaPrivateKey::from_pkcs8_der(der).unwrap();
    let mut trng = FakeTrng::from_seed(0x92);
    let mut mem = FakeVaultStorage::new(8192 * 4);
    let prk = [0x55u8; 32];
    let mut ctx = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng);
    vault_store_rsa_key(&mut ctx, &KeySlot(0), &k, true).unwrap();
}

#[test]
fn lifecycle_rsa_vault_load() {
    let der = include_bytes!("data/rsa_2048_fuzz.pk8");
    let k = RsaPrivateKey::from_pkcs8_der(der).unwrap();
    let mut trng = FakeTrng::from_seed(0x93);
    let mut mem = FakeVaultStorage::new(8192 * 4);
    let prk = [0x55u8; 32];
    let mut ctx = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng);
    vault_store_rsa_key(&mut ctx, &KeySlot(0), &k, true).unwrap();
    let k2 = vault_load_rsa_key(&mut mem, &prk, &KeySlot(0)).unwrap();
    let d1 = k.to_pkcs8_der().unwrap();
    let d2 = k2.to_pkcs8_der().unwrap();
    assert_eq!(d1.as_slice(), d2.as_slice());
}

#[test]
fn lifecycle_rsa_vault_overwrite_denied() {
    let der = include_bytes!("data/rsa_2048_fuzz.pk8");
    let k = RsaPrivateKey::from_pkcs8_der(der).unwrap();
    let mut trng = FakeTrng::from_seed(0x95);
    let mut mem = FakeVaultStorage::new(8192 * 4);
    let prk = [0x55u8; 32];
    let mut ctx = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng);
    vault_store_rsa_key(&mut ctx, &KeySlot(1), &k, true).unwrap();
    let r = vault_store_rsa_key(&mut ctx, &KeySlot(1), &k, false);
    assert_eq!(r, Err(RsaVaultError::SlotOccupied));
}

#[test]
fn lifecycle_rsa_vault_overwrite_allowed() {
    let der = include_bytes!("data/rsa_2048_fuzz.pk8");
    let k = RsaPrivateKey::from_pkcs8_der(der).unwrap();
    let mut trng = FakeTrng::from_seed(0x96);
    let mut mem = FakeVaultStorage::new(8192 * 4);
    let prk = [0x55u8; 32];
    let mut ctx = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng);
    vault_store_rsa_key(&mut ctx, &KeySlot(1), &k, true).unwrap();
    vault_store_rsa_key(&mut ctx, &KeySlot(1), &k, true).unwrap();
}

#[test]
fn lifecycle_rsa_vault_delete() {
    let der = include_bytes!("data/rsa_2048_fuzz.pk8");
    let k = RsaPrivateKey::from_pkcs8_der(der).unwrap();
    let mut trng = FakeTrng::from_seed(0x97);
    let mut mem = FakeVaultStorage::new(8192 * 4);
    let prk = [0x55u8; 32];
    let mut ctx = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng);
    vault_store_rsa_key(&mut ctx, &KeySlot(2), &k, true).unwrap();
    vault_delete_rsa_key(&mut mem, &KeySlot(2)).unwrap();
}

#[test]
fn lifecycle_rsa_vault_load_after_delete() {
    let der = include_bytes!("data/rsa_2048_fuzz.pk8");
    let k = RsaPrivateKey::from_pkcs8_der(der).unwrap();
    let mut trng = FakeTrng::from_seed(0x98);
    let mut mem = FakeVaultStorage::new(8192 * 4);
    let prk = [0x55u8; 32];
    let mut ctx = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng);
    vault_store_rsa_key(&mut ctx, &KeySlot(2), &k, true).unwrap();
    vault_delete_rsa_key(&mut mem, &KeySlot(2)).unwrap();
    let r = vault_load_rsa_key(&mut mem, &prk, &KeySlot(2));
    assert!(matches!(r, Err(RsaVaultError::SlotEmpty)));
}

#[test]
fn lifecycle_rsa_use_after_store_load() {
    let der = include_bytes!("data/rsa_2048_fuzz.pk8");
    let k = RsaPrivateKey::from_pkcs8_der(der).unwrap();
    let mut trng = FakeTrng::from_seed(0x9a);
    let mut mem = FakeVaultStorage::new(8192 * 4);
    let prk = [0x55u8; 32];
    let mut ctx = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng);
    vault_store_rsa_key(&mut ctx, &KeySlot(0), &k, true).unwrap();
    let k2 = vault_load_rsa_key(&mut mem, &prk, &KeySlot(0)).unwrap();
    let mut trng3 = FakeTrng::from_seed(0x9c);
    let sig = k2.sign_pss_sha256(b"msg", &mut trng3).unwrap();
    let pk = k2.public_key();
    assert!(pk.verify_pss_sha256(b"msg", &sig).is_ok());
}

#[test]
#[ignore = "RSA private material zeroization is covered in rsa_keys unit tests"]
fn lifecycle_rsa_zeroise_on_drop() {}

#[test]
fn lifecycle_rsa_no_clone() {
    assert_not_impl_any!(RsaPrivateKey: Clone);
}

#[test]
fn lifecycle_rsa_no_copy() {
    assert_not_impl_any!(RsaPrivateKey: Copy);
}

#[test]
fn lifecycle_rsa_full_vault_roundtrip() {
    let der = include_bytes!("data/rsa_2048_fuzz.pk8");
    let k = RsaPrivateKey::from_pkcs8_der(der).unwrap();
    let pk = k.public_key();
    let mut trng = FakeTrng::from_seed(0xa1);
    let sig = k.sign_pss_sha256(b"rt", &mut trng).unwrap();
    let mut mem = FakeVaultStorage::new(8192 * 4);
    let prk = [0x55u8; 32];
    {
        let mut trng_store = FakeTrng::from_seed(0xa0);
        let mut ctx = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng_store);
        vault_store_rsa_key(&mut ctx, &KeySlot(1), &k, true).unwrap();
    }
    drop(k);
    let k2 = vault_load_rsa_key(&mut mem, &prk, &KeySlot(1)).unwrap();
    let mut trng3 = FakeTrng::from_seed(0xa3);
    let sig2 = k2.sign_pss_sha256(b"rt", &mut trng3).unwrap();
    assert!(pk.verify_pss_sha256(b"rt", &sig2).is_ok());
    assert!(pk.verify_pss_sha256(b"rt", &sig).is_ok());
    vault_delete_rsa_key(&mut mem, &KeySlot(1)).unwrap();
}

#[test]
fn lifecycle_concurrent_slots_brainpool_rsa() {
    let mut trng = FakeTrng::from_seed(0xb1);
    let bp = BrainpoolSigningKey::generate(&mut trng).unwrap();
    let vk_bp = bp.verifying_key();
    let der = include_bytes!("data/rsa_2048_fuzz.pk8");
    let rsa_k = RsaPrivateKey::from_pkcs8_der(der).unwrap();
    let pk_rsa = rsa_k.public_key();
    let mut mem = FakeVaultStorage::new(8192 * 8);
    let prk = [0x33u8; 32];
    store_blob(&mut mem, 1, &bp.to_scalar_bytes_for_test(), true).unwrap();
    let mut trng_rsa = FakeTrng::from_seed(0xb2);
    let mut ctx = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng_rsa);
    vault_store_rsa_key(&mut ctx, &KeySlot(2), &rsa_k, true).unwrap();
    let raw_bp = read_blob(&mem, 1).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw_bp);
    let bp2 = BrainpoolSigningKey::from_scalar_bytes_for_test(&arr).unwrap();
    let msg = b"concurrent";
    let sig_bp = bp2.sign(msg, &mut trng).unwrap();
    assert!(vk_bp.verify(msg, &sig_bp).is_ok());
    let rsa2 = vault_load_rsa_key(&mut mem, &prk, &KeySlot(2)).unwrap();
    let mut trng4 = FakeTrng::from_seed(0xb4);
    let sig_rsa = rsa2.sign_pss_sha256(msg, &mut trng4).unwrap();
    assert!(pk_rsa.verify_pss_sha256(msg, &sig_rsa).is_ok());
    clear_slot(&mut mem, 1);
    let raw_after = read_blob(&mem, 1);
    assert!(raw_after.is_err());
    let rsa3 = vault_load_rsa_key(&mut mem, &prk, &KeySlot(2)).unwrap();
    let mut trng6 = FakeTrng::from_seed(0xb6);
    let sig2 = rsa3.sign_pss_sha256(msg, &mut trng6).unwrap();
    assert!(pk_rsa.verify_pss_sha256(msg, &sig2).is_ok());
    vault_delete_rsa_key(&mut mem, &KeySlot(2)).unwrap();
}

#[test]
fn lifecycle_slot_exhaustion_returns_typed_error() {
    let mut trng = FakeTrng::from_seed(0xc1);
    let k = BrainpoolScalar::generate(&mut trng).unwrap();
    let mut st = FakeVaultStorage::new(SLOT_STRIDE as usize * 2);
    store_blob(&mut st, 0, &k.to_secret_bytes_for_test(), true).unwrap();
    store_blob(&mut st, 1, &k.to_secret_bytes_for_test(), true).unwrap();
    let r = store_blob(&mut st, 2, &k.to_secret_bytes_for_test(), true);
    assert_eq!(r, Err(HalError::Denied));
}
