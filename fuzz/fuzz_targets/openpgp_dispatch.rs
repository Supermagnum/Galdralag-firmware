#![no_main]

//! Fuzz OpenPGP additions: APDU parse, `handle_apdu`, ECDH TLV parse, algorithm attributes,
//! and dalek key-type construction from arbitrary bytes (must not panic).

use galdr_core::fake_hal::{FakeMonotonicCounter, FakeTrng, FakeVaultStorage};
use galdr_core::VaultStorage;
use heapless::Vec as HVec;
use libfuzzer_sys::fuzz_target;
use pin_policy::{PinPolicyConfig, PinPolicyMachine};
use usb_personality::openpgp::commands::decipher::parse_ecdh_peer_public_key;
use usb_personality::openpgp::{
    aid::build_aid,
    apdu::CommandApdu,
    dispatch::handle_apdu,
    dos::{curve_oids, AlgorithmAttributes},
    do_store::DoStore,
    state::CardState,
    vault_backend::NoopZeroise,
    OpenPgpBackend,
    OpenPgpVaultBackend,
    DO_STORE_REGION_BYTES,
};
use vault::SEALED_KEY_REGION_END;

fn init_default_dos<S: VaultStorage>(do_store: &mut DoStore<S>) {
    let mut oid = HVec::<u8, 16>::new();
    for b in curve_oids::BRAINPOOL_P256R1 {
        oid.push(*b).unwrap();
    }
    let c1 = AlgorithmAttributes::Ecdsa {
        curve_oid: oid.clone(),
    }
    .to_bytes()
    .unwrap();
    let c2 = AlgorithmAttributes::Ecdh { curve_oid: oid.clone() }
        .to_bytes()
        .unwrap();
    let c3 = AlgorithmAttributes::Ecdsa { curve_oid: oid }.to_bytes().unwrap();
    let _ = do_store.write(0xC1, c1.as_slice());
    let _ = do_store.write(0xC2, c2.as_slice());
    let _ = do_store.write(0xC3, c3.as_slice());
    let _ = do_store.write(0xC4, &[5, 8, 3, 3, 3, 3, 3]);
    let _ = do_store.write(0x93, &[0x00, 0x00, 0x00]);
}

fn mk_backend() -> OpenPgpVaultBackend<
    FakeVaultStorage,
    FakeVaultStorage,
    FakeVaultStorage,
    FakeTrng,
    FakeMonotonicCounter,
    FakeMonotonicCounter,
    NoopZeroise,
    NoopZeroise,
> {
    let mut do_store = DoStore::new(FakeVaultStorage::new(DO_STORE_REGION_BYTES), 0);
    init_default_dos(&mut do_store);
    let pin_store = FakeVaultStorage::new(64);
    let key_store = FakeVaultStorage::new(SEALED_KEY_REGION_END);
    OpenPgpVaultBackend::new(
        do_store,
        pin_store,
        0,
        32,
        key_store,
        [0x55u8; 32],
        FakeTrng::from_seed(0xC0CC1D),
        build_aid(0x0000, [0x01, 0x02, 0x03, 0x04]),
        b"user1",
        b"adminadm",
        PinPolicyMachine::new(
            PinPolicyConfig::default(),
            FakeMonotonicCounter::new(0),
            NoopZeroise::default(),
        ),
        PinPolicyMachine::new(
            PinPolicyConfig::default(),
            FakeMonotonicCounter::new(0),
            NoopZeroise::default(),
        ),
        || FakeMonotonicCounter::new(0),
        || FakeMonotonicCounter::new(0),
    )
    .expect("fuzz backend")
}

fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[..32]);
        let _ = ed25519_dalek::VerifyingKey::from_bytes(&arr);
        let _ = ed25519_dalek::SigningKey::from_bytes(&arr);
        let _ = x25519_dalek::PublicKey::from(arr);
        let _ = x25519_dalek::StaticSecret::from(arr);
    }

    if !data.is_empty() {
        let end = data.len().min(48);
        let _ = AlgorithmAttributes::parse(&data[..end]);
    }

    if data.len() >= 4 {
        let _ = parse_ecdh_peer_public_key(data);
    }

    let raw = if data.len() > 512 { &data[..512] } else { data };
    let Ok(cmd) = CommandApdu::parse(raw) else {
        return;
    };

    let mut backend = mk_backend();
    if backend.is_termination_state() {
        return;
    }
    let mut state = CardState::new();
    let _ = handle_apdu(&cmd, &mut state, &mut backend);
});
