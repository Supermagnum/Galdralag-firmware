//! Integration-style OpenPGP APDU flows against a test [`usb_personality::openpgp::OpenPgpBackend`].

#![deny(unsafe_code)]

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ed25519_dalek::{Signature, VerifyingKey};
use galdr_core::fake_hal::{FakeMonotonicCounter, FakeTrng, FakeVaultStorage};
use galdr_core::VaultStorage;
use galdr_vault::brainpool::{BrainpoolPublicKey, BrainpoolScalar};
use galdr_vault::ecdsa_brainpool::{
    BrainpoolSignature, BrainpoolSigningKey, BrainpoolVerifyingKey,
};
use galdr_vault::KeyPurpose;
use galdr_vault::SEALED_KEY_REGION_END;
use heapless::Vec as HVec;
use pin_policy::{pin_compare, PinOutcome, PinPolicyConfig, PinPolicyMachine, ZeroisationTrigger};
use rand_core::RngCore;
use usb_personality::openpgp::{
    aid::build_aid,
    apdu::CommandApdu,
    backend::{OpenPgpAudit, OpenPgpBackend, OpenPgpBackendError, OpenPgpKeySlot},
    dispatch::handle_apdu,
    do_store::DoStore,
    dos::{curve_oids, pin_bytes_to_verifier_digest, AlgorithmAttributes},
    error::StatusWord,
    state::CardState,
    OpenPgpVaultBackend, DO_STORE_REGION_BYTES,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Default)]
struct ZeroiseFlag(pub bool);

impl ZeroisationTrigger for ZeroiseFlag {
    fn trigger_zeroisation(&mut self) {
        self.0 = true;
    }
}

#[derive(Default)]
struct VaultTestZ;

impl ZeroisationTrigger for VaultTestZ {
    fn trigger_zeroisation(&mut self) {}
}

#[derive(Clone)]
pub struct ZeroiseRecorder {
    called: Arc<AtomicBool>,
}

impl Default for ZeroiseRecorder {
    fn default() -> Self {
        Self {
            called: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl ZeroisationTrigger for ZeroiseRecorder {
    fn trigger_zeroisation(&mut self) {
        self.called.store(true, Ordering::SeqCst);
    }
}

impl ZeroiseRecorder {
    pub fn was_called(&self) -> bool {
        self.called.load(Ordering::SeqCst)
    }
}

fn mk_openpgp_vault() -> OpenPgpVaultBackend<
    FakeVaultStorage,
    FakeVaultStorage,
    FakeVaultStorage,
    FakeTrng,
    FakeMonotonicCounter,
    FakeMonotonicCounter,
    VaultTestZ,
    VaultTestZ,
> {
    let cfg = PinPolicyConfig::default();
    let do_store = DoStore::new(FakeVaultStorage::new(DO_STORE_REGION_BYTES), 0);
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
        PinPolicyMachine::new(cfg, FakeMonotonicCounter::new(0), VaultTestZ::default()),
        PinPolicyMachine::new(cfg, FakeMonotonicCounter::new(0), VaultTestZ::default()),
        || FakeMonotonicCounter::new(0),
        || FakeMonotonicCounter::new(0),
    )
    .expect("vault backend")
}

fn mk_openpgp_vault_user_zeroise(
    zu: ZeroiseRecorder,
) -> OpenPgpVaultBackend<
    FakeVaultStorage,
    FakeVaultStorage,
    FakeVaultStorage,
    FakeTrng,
    FakeMonotonicCounter,
    FakeMonotonicCounter,
    ZeroiseRecorder,
    VaultTestZ,
> {
    let cfg = PinPolicyConfig::default();
    let do_store = DoStore::new(FakeVaultStorage::new(DO_STORE_REGION_BYTES), 0);
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
        PinPolicyMachine::new(cfg, FakeMonotonicCounter::new(0), zu),
        PinPolicyMachine::new(cfg, FakeMonotonicCounter::new(0), VaultTestZ::default()),
        || FakeMonotonicCounter::new(0),
        || FakeMonotonicCounter::new(0),
    )
    .expect("vault backend")
}

fn mk_openpgp_vault_admin_zeroise(
    za: ZeroiseRecorder,
) -> OpenPgpVaultBackend<
    FakeVaultStorage,
    FakeVaultStorage,
    FakeVaultStorage,
    FakeTrng,
    FakeMonotonicCounter,
    FakeMonotonicCounter,
    VaultTestZ,
    ZeroiseRecorder,
> {
    let cfg = PinPolicyConfig::default();
    let do_store = DoStore::new(FakeVaultStorage::new(DO_STORE_REGION_BYTES), 0);
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
        PinPolicyMachine::new(cfg, FakeMonotonicCounter::new(0), VaultTestZ::default()),
        PinPolicyMachine::new(cfg, FakeMonotonicCounter::new(0), za),
        || FakeMonotonicCounter::new(0),
        || FakeMonotonicCounter::new(0),
    )
    .expect("vault backend")
}

fn mk_openpgp_vault_max5_pw1() -> OpenPgpVaultBackend<
    FakeVaultStorage,
    FakeVaultStorage,
    FakeVaultStorage,
    FakeTrng,
    FakeMonotonicCounter,
    FakeMonotonicCounter,
    VaultTestZ,
    VaultTestZ,
> {
    let cfg = PinPolicyConfig::try_with_max_attempts(5).expect("policy");
    let do_store = DoStore::new(FakeVaultStorage::new(DO_STORE_REGION_BYTES), 0);
    let pin_store = FakeVaultStorage::new(64);
    let key_store = FakeVaultStorage::new(SEALED_KEY_REGION_END);
    OpenPgpVaultBackend::new_with_policy(
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
        cfg,
        cfg,
        || FakeMonotonicCounter::new(0),
        || FakeMonotonicCounter::new(0),
    )
    .expect("vault backend")
}

fn init_vault_default_dos<S: VaultStorage>(do_store: &mut DoStore<S>) {
    let mut oid = HVec::new();
    for b in curve_oids::BRAINPOOL_P256R1 {
        oid.push(*b).unwrap();
    }
    let c1 = AlgorithmAttributes::Ecdsa {
        curve_oid: oid.clone(),
    }
    .to_bytes()
    .unwrap();
    let c2 = AlgorithmAttributes::Ecdh {
        curve_oid: oid.clone(),
    }
    .to_bytes()
    .unwrap();
    let c3 = AlgorithmAttributes::Ecdsa { curve_oid: oid }
        .to_bytes()
        .unwrap();
    let _ = do_store.write(0xC1, c1.as_slice());
    let _ = do_store.write(0xC2, c2.as_slice());
    let _ = do_store.write(0xC3, c3.as_slice());
    let _ = do_store.write(0xC4, &[5, 8, 3, 3, 3, 3, 3]);
    let _ = do_store.write(0x93, &[0x00, 0x00, 0x00]);
}

/// Test backend: Brainpool P-256 signing, SHA-256 PIN verifiers, [`PinPolicyMachine`] ordering.
struct MockOpenPgp {
    aid: [u8; 16],
    do_store: DoStore<FakeVaultStorage>,
    pin_vault: FakeVaultStorage,
    user_verifier: [u8; 32],
    admin_verifier: [u8; 32],
    user_machine: PinPolicyMachine<FakeMonotonicCounter, ZeroiseFlag>,
    admin_machine: PinPolicyMachine<FakeMonotonicCounter, ZeroiseFlag>,
    sig_key: Option<BrainpoolSigningKey>,
    aut_key: Option<BrainpoolSigningKey>,
    dec_key: Option<BrainpoolScalar>,
    trng: FakeTrng,
    sig_counter: u32,
    termination: bool,
    audit: u32,
}

impl MockOpenPgp {
    fn new(user_pin: &[u8], admin_pin: &[u8]) -> Self {
        let uv = pin_bytes_to_verifier_digest(user_pin);
        let av = pin_bytes_to_verifier_digest(admin_pin);
        let cfg = PinPolicyConfig::default();
        let storage = FakeVaultStorage::new(DO_STORE_REGION_BYTES);
        let mut pin_vault = FakeVaultStorage::new(64);
        let _ = pin_vault.write(0, &uv);
        let _ = pin_vault.write(32, &av);
        Self {
            aid: build_aid(0x0000, [0x01, 0x02, 0x03, 0x04]),
            do_store: DoStore::new(storage, 0),
            pin_vault,
            user_verifier: uv,
            admin_verifier: av,
            user_machine: PinPolicyMachine::new(
                cfg,
                FakeMonotonicCounter::new(0),
                ZeroiseFlag::default(),
            ),
            admin_machine: PinPolicyMachine::new(
                cfg,
                FakeMonotonicCounter::new(0),
                ZeroiseFlag::default(),
            ),
            sig_key: None,
            aut_key: None,
            dec_key: None,
            trng: FakeTrng::from_seed(0xC0CC1D),
            sig_counter: 0,
            termination: false,
            audit: 0,
        }
    }

    fn init_default_dos(&mut self) {
        let mut oid = HVec::new();
        for b in curve_oids::BRAINPOOL_P256R1 {
            oid.push(*b).unwrap();
        }
        let c1 = AlgorithmAttributes::Ecdsa {
            curve_oid: oid.clone(),
        }
        .to_bytes()
        .unwrap();
        let c2 = AlgorithmAttributes::Ecdh {
            curve_oid: oid.clone(),
        }
        .to_bytes()
        .unwrap();
        let c3 = AlgorithmAttributes::Ecdsa { curve_oid: oid }
            .to_bytes()
            .unwrap();
        let _ = self.do_store.write(0xC1, c1.as_slice());
        let _ = self.do_store.write(0xC2, c2.as_slice());
        let _ = self.do_store.write(0xC3, c3.as_slice());
        let _ = self.do_store.write(0xC4, &[5, 8, 3, 3, 3, 3, 3]);
        let _ = self.do_store.write(0x93, &[0x00, 0x00, 0x00]);
    }

    fn reset_user_machine(&mut self) {
        let cfg = self.user_machine.config;
        self.user_machine =
            PinPolicyMachine::new(cfg, FakeMonotonicCounter::new(0), ZeroiseFlag::default());
    }

    fn reset_admin_machine(&mut self) {
        let cfg = self.admin_machine.config;
        self.admin_machine =
            PinPolicyMachine::new(cfg, FakeMonotonicCounter::new(0), ZeroiseFlag::default());
    }

    fn persist_pin_hashes(&mut self) -> Result<(), OpenPgpBackendError> {
        self.pin_vault
            .write(0, &self.user_verifier)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        self.pin_vault
            .write(32, &self.admin_verifier)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        Ok(())
    }

    fn ensure_not_terminated(&self) -> Result<(), OpenPgpBackendError> {
        if self.termination {
            return Err(OpenPgpBackendError::Status(StatusWord::TerminationState));
        }
        Ok(())
    }

    fn verify_user(&mut self, pin: &[u8]) -> Result<(), OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let d = pin_bytes_to_verifier_digest(pin);
        let exp = self.user_verifier;
        let r = self
            .user_machine
            .submit_attempt(|| pin_compare(&d, &exp))
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        match r {
            PinOutcome::Success => Ok(()),
            PinOutcome::Failed { attempts_used } => {
                let max = self.user_machine.config.max_attempts;
                let rem = max.saturating_sub(attempts_used);
                Err(OpenPgpBackendError::Status(
                    StatusWord::VerificationFailedRetries(rem as u8),
                ))
            }
            PinOutcome::Breach => {
                self.termination = true;
                Err(OpenPgpBackendError::Status(StatusWord::AuthMethodBlocked))
            }
        }
    }

    fn verify_admin(&mut self, pin: &[u8]) -> Result<(), OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let d = pin_bytes_to_verifier_digest(pin);
        let exp = self.admin_verifier;
        let r = self
            .admin_machine
            .submit_attempt(|| pin_compare(&d, &exp))
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        match r {
            PinOutcome::Success => Ok(()),
            PinOutcome::Failed { attempts_used } => {
                let max = self.admin_machine.config.max_attempts;
                let rem = max.saturating_sub(attempts_used);
                Err(OpenPgpBackendError::Status(
                    StatusWord::VerificationFailedRetries(rem as u8),
                ))
            }
            PinOutcome::Breach => {
                self.termination = true;
                Err(OpenPgpBackendError::Status(StatusWord::AuthMethodBlocked))
            }
        }
    }
}

impl OpenPgpAudit for MockOpenPgp {
    fn log_event(&mut self, code: u32) {
        self.audit ^= code;
    }
}

impl OpenPgpBackend for MockOpenPgp {
    fn is_termination_state(&self) -> bool {
        self.termination
    }

    fn aid_bytes(&self) -> &[u8] {
        &self.aid
    }

    fn pw_status_bytes(&self) -> [u8; 7] {
        self.do_store
            .read(0xC4)
            .map(|v| {
                let mut a = [0u8; 7];
                let n = v.len().min(7);
                a[..n].copy_from_slice(&v[..n]);
                a
            })
            .unwrap_or([5, 8, 3, 3, 3, 3, 3])
    }

    fn user_pin_retries_remaining(&self) -> u8 {
        3
    }

    fn admin_pin_retries_remaining(&self) -> u8 {
        3
    }

    fn verify_pw1_sign(&mut self, pin: &[u8]) -> Result<(), OpenPgpBackendError> {
        self.verify_user(pin)
    }

    fn verify_pw1_other(&mut self, pin: &[u8]) -> Result<(), OpenPgpBackendError> {
        self.verify_user(pin)
    }

    fn verify_pw3(&mut self, pin: &[u8]) -> Result<(), OpenPgpBackendError> {
        self.verify_admin(pin)
    }

    fn change_pin(
        &mut self,
        pw3: bool,
        old_pin: &[u8],
        new_pin: &[u8],
    ) -> Result<(), OpenPgpBackendError> {
        let max_len = if pw3 {
            self.pw_status_bytes()[1] as usize
        } else {
            self.pw_status_bytes()[0] as usize
        };
        if new_pin.len() > max_len {
            return Err(OpenPgpBackendError::Status(StatusWord::IncorrectParameters));
        }
        if pw3 {
            self.verify_admin(old_pin)?;
            self.admin_verifier = pin_bytes_to_verifier_digest(new_pin);
            self.persist_pin_hashes()?;
            self.reset_admin_machine();
        } else {
            self.verify_user(old_pin)?;
            self.user_verifier = pin_bytes_to_verifier_digest(new_pin);
            self.persist_pin_hashes()?;
            self.reset_user_machine();
        }
        Ok(())
    }

    fn set_pw1_verifier_admin_only(&mut self, new_pin: &[u8]) -> Result<(), OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let pw = self.pw_status_bytes();
        let min_len = pw[0] as usize;
        let max_len = pw[0] as usize;
        if new_pin.len() < min_len {
            return Err(OpenPgpBackendError::Status(StatusWord::WrongLength));
        }
        if new_pin.len() > max_len {
            return Err(OpenPgpBackendError::Status(StatusWord::IncorrectParameters));
        }
        self.user_verifier = pin_bytes_to_verifier_digest(new_pin);
        self.persist_pin_hashes()?;
        Ok(())
    }

    fn reset_pw1_retry_counter(&mut self) -> Result<(), OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        self.reset_user_machine();
        Ok(())
    }

    fn get_do(&self, tag: u16) -> Result<HVec<u8, 512>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let mut out = HVec::new();
        if let Some(v) = self.do_store.read(tag) {
            for b in v.iter() {
                out.push(*b)
                    .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
            }
        }
        Ok(out)
    }

    fn put_do(&mut self, tag: u16, value: &[u8]) -> Result<(), OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        self.do_store
            .write(tag, value)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))
    }

    fn algorithm_attributes(&self, slot: OpenPgpKeySlot) -> AlgorithmAttributes {
        let tag = match slot {
            OpenPgpKeySlot::Sig => 0xC1,
            OpenPgpKeySlot::Dec => 0xC2,
            OpenPgpKeySlot::Aut => 0xC3,
        };
        if let Some(data) = self.do_store.read(tag) {
            if let Ok(a) = AlgorithmAttributes::parse(data.as_slice()) {
                return a;
            }
        }
        let mut oid = HVec::new();
        for b in curve_oids::BRAINPOOL_P256R1 {
            oid.push(*b).unwrap();
        }
        match slot {
            OpenPgpKeySlot::Dec => AlgorithmAttributes::Ecdh { curve_oid: oid },
            _ => AlgorithmAttributes::Ecdsa { curve_oid: oid },
        }
    }

    fn pso_sign_hash(&mut self, hash: &[u8]) -> Result<HVec<u8, 512>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let sk = self.sig_key.as_ref().ok_or(OpenPgpBackendError::Status(
            StatusWord::ReferenceDataNotFound,
        ))?;
        let sig = sk
            .sign_handshake_sha256_prehash(hash, &mut self.trng)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        let mut out = HVec::new();
        for b in sig.der_bytes() {
            out.push(*b)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        }
        Ok(out)
    }

    fn pso_decipher(&mut self, _data: &[u8]) -> Result<HVec<u8, 512>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        Err(OpenPgpBackendError::Status(
            StatusWord::ReferenceDataNotFound,
        ))
    }

    fn ecdh_dec(
        &mut self,
        _purpose: KeyPurpose,
        peer_public_key: &[u8],
    ) -> Result<HVec<u8, 64>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let sk = self.dec_key.as_ref().ok_or(OpenPgpBackendError::Status(
            StatusWord::ReferenceDataNotFound,
        ))?;
        let pk = BrainpoolPublicKey::from_sec1(peer_public_key)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::IncorrectParameters))?;
        let sec = sk
            .diffie_hellman(&pk)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        let mut out = HVec::new();
        for b in sec.as_bytes() {
            out.push(*b)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        }
        Ok(out)
    }

    fn get_challenge(&mut self, len: usize) -> Result<HVec<u8, 64>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let mut out = HVec::new();
        let mut buf = [0u8; 64];
        self.trng.fill_bytes(&mut buf[..len]);
        for b in &buf[..len] {
            out.push(*b)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        }
        Ok(out)
    }

    fn ed25519_sign(
        &mut self,
        _purpose: KeyPurpose,
        _message: &[u8],
    ) -> Result<HVec<u8, 64>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        Err(OpenPgpBackendError::Status(
            StatusWord::ReferenceDataNotFound,
        ))
    }

    fn x25519_ecdh(
        &mut self,
        _purpose: KeyPurpose,
        _peer_public_key: &[u8],
    ) -> Result<HVec<u8, 32>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        Err(OpenPgpBackendError::Status(
            StatusWord::ReferenceDataNotFound,
        ))
    }

    fn internal_authenticate(
        &mut self,
        challenge: &[u8],
    ) -> Result<HVec<u8, 512>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let sk = self.aut_key.as_ref().ok_or(OpenPgpBackendError::Status(
            StatusWord::ReferenceDataNotFound,
        ))?;
        let sig = sk
            .sign_handshake_sha256_prehash(challenge, &mut self.trng)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        let mut out = HVec::new();
        for b in sig.der_bytes() {
            out.push(*b)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        }
        Ok(out)
    }

    fn generate_or_read_key(
        &mut self,
        p1: u8,
        slot: OpenPgpKeySlot,
    ) -> Result<HVec<u8, 512>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        if p1 == 0x81 {
            let sec1 = match slot {
                OpenPgpKeySlot::Sig => {
                    let vk = self.sig_key.as_ref().map(|k| k.verifying_key()).ok_or(
                        OpenPgpBackendError::Status(StatusWord::ReferenceDataNotFound),
                    )?;
                    vk.to_sec1_compressed()
                }
                OpenPgpKeySlot::Aut => {
                    let vk = self.aut_key.as_ref().map(|k| k.verifying_key()).ok_or(
                        OpenPgpBackendError::Status(StatusWord::ReferenceDataNotFound),
                    )?;
                    vk.to_sec1_compressed()
                }
                OpenPgpKeySlot::Dec => {
                    let pk = self
                        .dec_key
                        .as_ref()
                        .and_then(|k| k.public_key().ok())
                        .ok_or(OpenPgpBackendError::Status(
                            StatusWord::ReferenceDataNotFound,
                        ))?;
                    pk.to_sec1_compressed()
                }
            };
            let mut out = HVec::new();
            for b in sec1 {
                out.push(b)
                    .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
            }
            return Ok(out);
        }
        if p1 != 0x80 {
            return Err(OpenPgpBackendError::Status(StatusWord::WrongParametersP1P2));
        }
        let mut trng = FakeTrng::from_seed(0x51EE_0000);
        match slot {
            OpenPgpKeySlot::Sig => {
                let sk = BrainpoolSigningKey::generate(&mut trng)
                    .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                self.sig_key = Some(sk);
                let vk = self.sig_key.as_ref().unwrap().verifying_key();
                let sec1 = vk.to_sec1_compressed();
                let mut out = HVec::new();
                for b in sec1 {
                    out.push(b)
                        .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                }
                Ok(out)
            }
            OpenPgpKeySlot::Aut => {
                let sk = BrainpoolSigningKey::generate(&mut trng)
                    .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                self.aut_key = Some(sk);
                let vk = self.aut_key.as_ref().unwrap().verifying_key();
                let sec1 = vk.to_sec1_compressed();
                let mut out = HVec::new();
                for b in sec1 {
                    out.push(b)
                        .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                }
                Ok(out)
            }
            OpenPgpKeySlot::Dec => {
                let sk = BrainpoolScalar::generate(&mut trng)
                    .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                self.dec_key = Some(sk);
                let vk = self
                    .dec_key
                    .as_ref()
                    .unwrap()
                    .public_key()
                    .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                let sec1 = vk.to_sec1_compressed();
                let mut out = HVec::new();
                for b in sec1 {
                    out.push(b)
                        .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                }
                Ok(out)
            }
        }
    }

    fn increment_signature_counter(&mut self) -> Result<(), OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        self.sig_counter = self.sig_counter.saturating_add(1);
        let c = self.sig_counter;
        let buf = [
            ((c >> 16) & 0xFF) as u8,
            ((c >> 8) & 0xFF) as u8,
            (c & 0xFF) as u8,
        ];
        self.do_store
            .write(0x93, &buf)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        Ok(())
    }

    fn on_lock_disconnect(&mut self) {
        self.audit = 0;
    }
}

fn apdu_hex(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u8>) -> Vec<u8> {
    let mut v = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        assert!(data.len() <= 255);
        v.push(data.len() as u8);
        v.extend_from_slice(data);
    }
    if let Some(l) = le {
        v.push(l);
    }
    v
}

/// Build PSO:DECIPHER ECDH command data (§7.2.11): `0xA6` / `0x7F49` / `0x86` with SEC1 peer key.
fn ecdh_command_data(peer_sec1_uncompressed: &[u8]) -> Vec<u8> {
    let mut inner2 = Vec::new();
    inner2.push(0x86);
    inner2.push(peer_sec1_uncompressed.len() as u8);
    inner2.extend_from_slice(peer_sec1_uncompressed);
    let mut inner = Vec::new();
    inner.push(0x7F);
    inner.push(0x49);
    inner.push(inner2.len() as u8);
    inner.extend_from_slice(&inner2);
    let mut outer = Vec::new();
    outer.push(0xA6);
    outer.push(inner.len() as u8);
    outer.extend_from_slice(&inner);
    outer
}

#[test]
fn test_select_openpgp_aid() {
    let mut b = MockOpenPgp::new(b"user1", b"adminadm");
    b.init_default_dos();
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    let raw = apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None);
    let cmd = CommandApdu::parse(&raw).unwrap();
    let r = handle_apdu(&cmd, &mut st, &mut b);
    assert_eq!(r.sw1, 0x90);
    assert_eq!(r.sw2, 0x00);
}

#[test]
fn test_get_data_aid() {
    let mut b = MockOpenPgp::new(b"user1", b"adminadm");
    b.init_default_dos();
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    let raw = apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None);
    handle_apdu(&CommandApdu::parse(&raw).unwrap(), &mut st, &mut b);
    let g = apdu_hex(0x00, 0xCA, 0x00, 0x4F, &[], Some(0x00));
    let r = handle_apdu(&CommandApdu::parse(&g).unwrap(), &mut st, &mut b);
    assert_eq!(r.sw1, 0x90);
    assert!(r.data.len() >= 5);
    assert!(r
        .data
        .as_slice()
        .windows(5)
        .any(|w| w == usb_personality::openpgp::OPENPGP_AID_PREFIX));
}

#[test]
fn test_verify_user_pin_correct() {
    let mut b = MockOpenPgp::new(b"user1", b"adminadm");
    b.init_default_dos();
    let mut st = CardState::new();
    let raw = apdu_hex(0x00, 0x20, 0x00, 0x81, b"user1", None);
    let r = handle_apdu(&CommandApdu::parse(&raw).unwrap(), &mut st, &mut b);
    assert_eq!((r.sw1, r.sw2), (0x90, 0x00));
}

#[test]
fn test_verify_user_pin_wrong() {
    let mut b = MockOpenPgp::new(b"user1", b"adminadm");
    b.init_default_dos();
    let mut st = CardState::new();
    let raw = apdu_hex(0x00, 0x20, 0x00, 0x81, b"wrong", None);
    let r = handle_apdu(&CommandApdu::parse(&raw).unwrap(), &mut st, &mut b);
    assert_eq!(r.sw1, 0x63);
}

#[test]
fn test_sign_requires_pw1() {
    let mut b = MockOpenPgp::new(b"user1", b"adminadm");
    b.init_default_dos();
    let mut st = CardState::new();
    let hash = [0x55u8; 32];
    let raw = apdu_hex(0x00, 0x2A, 0x9E, 0x9A, &hash, Some(0x00));
    let r = handle_apdu(&CommandApdu::parse(&raw).unwrap(), &mut st, &mut b);
    assert_eq!((r.sw1, r.sw2), (0x69, 0x82));
}

#[test]
fn test_sign_with_verified_pw1() {
    let mut b = MockOpenPgp::new(b"user1", b"adminadm");
    b.init_default_dos();
    let mut st = CardState::new();
    let v = apdu_hex(0x00, 0x20, 0x00, 0x83, b"adminadm", None);
    handle_apdu(&CommandApdu::parse(&v).unwrap(), &mut st, &mut b);
    let g = apdu_hex(0x00, 0x47, 0x80, 0xB6, &[], Some(0x00));
    handle_apdu(&CommandApdu::parse(&g).unwrap(), &mut st, &mut b);
    let v2 = apdu_hex(0x00, 0x20, 0x00, 0x81, b"user1", None);
    handle_apdu(&CommandApdu::parse(&v2).unwrap(), &mut st, &mut b);
    let hash = [0x33u8; 32];
    let raw = apdu_hex(0x00, 0x2A, 0x9E, 0x9A, &hash, Some(0x00));
    let r = handle_apdu(&CommandApdu::parse(&raw).unwrap(), &mut st, &mut b);
    assert_eq!(r.sw1, 0x90);
    assert!(r.data.len() > 8);
    assert_eq!(r.data.as_slice()[0], 0x30);
}

#[test]
fn test_signature_counter_increments() {
    let mut b = MockOpenPgp::new(b"user1", b"adminadm");
    b.init_default_dos();
    let mut st = CardState::new();
    let v = apdu_hex(0x00, 0x20, 0x00, 0x83, b"adminadm", None);
    handle_apdu(&CommandApdu::parse(&v).unwrap(), &mut st, &mut b);
    let g = apdu_hex(0x00, 0x47, 0x80, 0xB6, &[], Some(0x00));
    handle_apdu(&CommandApdu::parse(&g).unwrap(), &mut st, &mut b);
    for _ in 0..2 {
        let v2 = apdu_hex(0x00, 0x20, 0x00, 0x81, b"user1", None);
        handle_apdu(&CommandApdu::parse(&v2).unwrap(), &mut st, &mut b);
        let hash = [0x44u8; 32];
        let raw = apdu_hex(0x00, 0x2A, 0x9E, 0x9A, &hash, Some(0x00));
        handle_apdu(&CommandApdu::parse(&raw).unwrap(), &mut st, &mut b);
    }
    let gd = apdu_hex(0x00, 0xCA, 0x00, 0x93, &[], Some(0x00));
    let r = handle_apdu(&CommandApdu::parse(&gd).unwrap(), &mut st, &mut b);
    assert_eq!(r.data.as_slice(), &[0x00, 0x00, 0x02]);
}

#[test]
fn test_pso_decipher_ecdh_returns_shared_secret() {
    let mut b = MockOpenPgp::new(b"user1", b"adminadm");
    b.init_default_dos();
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    let v = apdu_hex(0x00, 0x20, 0x00, 0x83, b"adminadm", None);
    handle_apdu(&CommandApdu::parse(&v).unwrap(), &mut st, &mut b);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x80, 0xB8, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    let v2 = apdu_hex(0x00, 0x20, 0x00, 0x82, b"user1", None);
    handle_apdu(&CommandApdu::parse(&v2).unwrap(), &mut st, &mut b);

    let mut trng = FakeTrng::from_seed(0xDEC0DE);
    let peer_sk = BrainpoolScalar::generate(&mut trng).expect("peer sk");
    let peer_pk = peer_sk.public_key().expect("peer pk");
    let card_pk = b.dec_key.as_ref().expect("dec").public_key().expect("pk");
    let expected = peer_sk
        .diffie_hellman(&card_pk)
        .expect("dh")
        .as_bytes()
        .to_vec();

    let cmd_data = ecdh_command_data(&peer_pk.to_sec1_uncompressed());
    let raw = apdu_hex(0x00, 0x2A, 0x80, 0x86, &cmd_data, Some(0x00));
    let r = handle_apdu(&CommandApdu::parse(&raw).unwrap(), &mut st, &mut b);
    assert_eq!((r.sw1, r.sw2), (0x90, 0x00));
    assert_eq!(r.data.len(), 32);
    assert_eq!(r.data.as_slice(), expected.as_slice());
}

#[test]
fn test_pso_decipher_ecdh_requires_pw1_other() {
    let mut b = MockOpenPgp::new(b"user1", b"adminadm");
    b.init_default_dos();
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    let v = apdu_hex(0x00, 0x20, 0x00, 0x83, b"adminadm", None);
    handle_apdu(&CommandApdu::parse(&v).unwrap(), &mut st, &mut b);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x80, 0xB8, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );

    let mut trng = FakeTrng::from_seed(0xDEC0DE);
    let peer_sk = BrainpoolScalar::generate(&mut trng).expect("peer sk");
    let peer_pk = peer_sk.public_key().expect("peer pk");
    let cmd_data = ecdh_command_data(&peer_pk.to_sec1_uncompressed());
    let raw = apdu_hex(0x00, 0x2A, 0x80, 0x86, &cmd_data, Some(0x00));
    let r = handle_apdu(&CommandApdu::parse(&raw).unwrap(), &mut st, &mut b);
    assert_eq!((r.sw1, r.sw2), (0x69, 0x82));
}

#[test]
fn test_change_reference_data_pw1() {
    let mut b = MockOpenPgp::new(b"user1", b"adminadm");
    b.init_default_dos();
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x81, b"user1", None)).unwrap(),
        &mut st,
        &mut b,
    );
    let change = apdu_hex(0x00, 0x24, 0x00, 0x81, b"user1new11", None);
    let r = handle_apdu(&CommandApdu::parse(&change).unwrap(), &mut st, &mut b);
    assert_eq!((r.sw1, r.sw2), (0x90, 0x00));

    let r_new = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x81, b"new11", None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r_new.sw1, r_new.sw2), (0x90, 0x00));

    let r_old = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x81, b"user1", None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!(r_old.sw1, 0x63);
}

#[test]
fn test_put_data_name_persists_across_card_reset() {
    let mut b = MockOpenPgp::new(b"user1", b"adminadm");
    b.init_default_dos();
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x83, b"adminadm", None)).unwrap(),
        &mut st,
        &mut b,
    );
    let name = b"PersistName";
    let put = apdu_hex(0x00, 0xDA, 0x00, 0x5B, name, None);
    let r = handle_apdu(&CommandApdu::parse(&put).unwrap(), &mut st, &mut b);
    assert_eq!((r.sw1, r.sw2), (0x90, 0x00));

    st.reset();

    let gd = apdu_hex(0x00, 0xCA, 0x00, 0x5B, &[], Some(0x00));
    let r2 = handle_apdu(&CommandApdu::parse(&gd).unwrap(), &mut st, &mut b);
    assert_eq!((r2.sw1, r2.sw2), (0x90, 0x00));
    assert_eq!(r2.data.as_slice(), name.as_slice());
}

#[test]
fn key_survives_power_cycle() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x83, b"adminadm", None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x80, 0xB6, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    let pk1 = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x81, 0xB6, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((pk1.sw1, pk1.sw2), (0x90, 0x00));
    st.reset();
    b.load_private_keys().expect("reload keys");
    let pk2 = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x81, 0xB6, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!(pk1.data.as_slice(), pk2.data.as_slice());
    let v2 = apdu_hex(0x00, 0x20, 0x00, 0x81, b"user1", None);
    handle_apdu(&CommandApdu::parse(&v2).unwrap(), &mut st, &mut b);
    let hash = [0x33u8; 32];
    let sig_r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x2A, 0x9E, 0x9A, &hash, Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((sig_r.sw1, sig_r.sw2), (0x90, 0x00));
    let vk = BrainpoolVerifyingKey::from_sec1(pk2.data.as_slice()).expect("vk");
    let sig = BrainpoolSignature::from_der_bytes(sig_r.data.as_slice()).expect("sig");
    vk.verify_handshake_sha256_prehash(&hash, &sig)
        .expect("signature must verify after reload");
}

#[test]
fn empty_slot_after_factory_reset() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    b.load_private_keys().expect("load");
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    let raw = apdu_hex(0x00, 0x20, 0x00, 0x81, b"user1", None);
    handle_apdu(&CommandApdu::parse(&raw).unwrap(), &mut st, &mut b);
    let hash = [0x44u8; 32];
    let r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x2A, 0x9E, 0x9A, &hash, Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r.sw1, r.sw2), (0x6A, 0x88));
}

#[test]
fn reset_retry_requires_pw3() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    let r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x2C, 0x00, 0x81, b"newpw", None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r.sw1, r.sw2), (0x69, 0x82));
}

#[test]
fn reset_retry_sets_new_pin() {
    let mut b = mk_openpgp_vault_max5_pw1();
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    for _ in 0..3 {
        let r = handle_apdu(
            &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x81, b"wrong", None)).unwrap(),
            &mut st,
            &mut b,
        );
        assert_eq!(r.sw1, 0x63);
    }
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x83, b"adminadm", None)).unwrap(),
        &mut st,
        &mut b,
    );
    let r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x2C, 0x00, 0x81, b"newpw", None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r.sw1, r.sw2), (0x90, 0x00));
    let r_ok = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x81, b"newpw", None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r_ok.sw1, r_ok.sw2), (0x90, 0x00));
    let r_old = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x81, b"user1", None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!(r_old.sw1, 0x63);
    assert_eq!(r_old.sw2, 0xC4);
}

#[test]
fn reset_retry_p1_02_returns_not_found() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x83, b"adminadm", None)).unwrap(),
        &mut st,
        &mut b,
    );
    let r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x2C, 0x02, 0x81, &[], None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r.sw1, r.sw2), (0x6A, 0x88));
}

#[test]
fn pin_exhaustion_pw1_triggers_zeroise() {
    let zu = ZeroiseRecorder::default();
    let zu_chk = zu.clone();
    let mut b = mk_openpgp_vault_user_zeroise(zu);
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    for _ in 0..4 {
        handle_apdu(
            &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x81, b"wrong", None)).unwrap(),
            &mut st,
            &mut b,
        );
    }
    assert!(zu_chk.was_called());
    assert!(OpenPgpBackend::is_termination_state(&b));
    let r_sel = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r_sel.sw1, r_sel.sw2), (0x62, 0x85));
    let r_v = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x81, b"user1", None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r_v.sw1, r_v.sw2), (0x69, 0x83));
}

#[test]
fn pin_exhaustion_pw3_triggers_zeroise() {
    let za = ZeroiseRecorder::default();
    let za_chk = za.clone();
    let mut b = mk_openpgp_vault_admin_zeroise(za);
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    for _ in 0..4 {
        handle_apdu(
            &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x83, b"badad", None)).unwrap(),
            &mut st,
            &mut b,
        );
    }
    assert!(za_chk.was_called());
    assert!(OpenPgpBackend::is_termination_state(&b));
}

#[test]
fn zeroise_state_blocks_all_commands() {
    let zu = ZeroiseRecorder::default();
    let mut b = mk_openpgp_vault_user_zeroise(zu);
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    for _ in 0..4 {
        handle_apdu(
            &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x81, b"wrong", None)).unwrap(),
            &mut st,
            &mut b,
        );
    }
    let hash = [0x33u8; 32];
    let r_pso = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x2A, 0x9E, 0x9A, &hash, Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r_pso.sw1, r_pso.sw2), (0x62, 0x85));
    let r_gd = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xCA, 0x00, 0x4F, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r_gd.sw1, r_gd.sw2), (0x62, 0x85));
    let r_gen = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x80, 0xB6, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r_gen.sw1, r_gen.sw2), (0x62, 0x85));
}

fn ecdh_command_data_x25519(peer_raw32: &[u8]) -> std::vec::Vec<u8> {
    assert_eq!(peer_raw32.len(), 32);
    let mut inner2 = std::vec::Vec::new();
    inner2.push(0x86);
    inner2.push(32);
    inner2.extend_from_slice(peer_raw32);
    let mut inner = std::vec::Vec::new();
    inner.push(0x7F);
    inner.push(0x49);
    inner.push(inner2.len() as u8);
    inner.extend_from_slice(&inner2);
    let mut outer = std::vec::Vec::new();
    outer.push(0xA6);
    outer.push(inner.len() as u8);
    outer.extend_from_slice(&inner);
    outer
}

#[test]
fn get_challenge_returns_requested_length() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    let r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x84, 0x00, 0x00, &[], Some(32))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r.sw1, r.sw2), (0x90, 0x00));
    assert_eq!(r.data.len(), 32);
}

#[test]
fn get_challenge_rejects_zero() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    let cmd = CommandApdu {
        cla: 0x00,
        ins: 0x84,
        p1: 0x00,
        p2: 0x00,
        data: HVec::new(),
        le: Some(0),
    };
    let r = handle_apdu(&cmd, &mut st, &mut b);
    assert_eq!((r.sw1, r.sw2), (0x67, 0x00));
}

#[test]
fn get_challenge_rejects_oversized() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    let r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x84, 0x00, 0x00, &[], Some(255))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r.sw1, r.sw2), (0x67, 0x00));
}

#[test]
fn mse_set_dec_curve25519() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    let r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x22, 0x41, 0xB8, &[0x83, 0x01, 0x03], None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r.sw1, r.sw2), (0x90, 0x00));
    assert_eq!(st.mse_dec_key_ref, Some(3));
}

#[test]
fn mse_set_sig_ed25519() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    let r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x22, 0x41, 0xB6, &[0x83, 0x01, 0x01], None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r.sw1, r.sw2), (0x90, 0x00));
}

#[test]
fn mse_wrong_p1() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    let r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x22, 0x00, 0xB8, &[0x83, 0x01, 0x03], None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r.sw1, r.sw2), (0x69, 0x85));
}

#[test]
fn mse_malformed_data() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    let r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(
            0x00,
            0x22,
            0x41,
            0xB8,
            &[0x83, 0x02, 0x01, 0x00],
            None,
        ))
        .unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((r.sw1, r.sw2), (0x6A, 0x80));
}

#[test]
fn mse_reset_clears_refs() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x22, 0x41, 0xB8, &[0x83, 0x01, 0x03], None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x22, 0x41, 0xB6, &[0x83, 0x01, 0x01], None)).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!(st.mse_dec_key_ref, Some(3));
    assert_eq!(st.mse_sig_key_ref, Some(1));
    st.reset();
    assert!(st.mse_dec_key_ref.is_none());
    assert!(st.mse_sig_key_ref.is_none());
    assert!(st.mse_aut_key_ref.is_none());
}

#[test]
fn ed25519_sign_and_verify() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut oid = HVec::new();
    for x in curve_oids::ED25519 {
        oid.push(*x).unwrap();
    }
    let ed = AlgorithmAttributes::EdDsa { curve_oid: oid }
        .to_bytes()
        .unwrap();
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x83, b"adminadm", None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xDA, 0x00, 0xC1, ed.as_slice(), None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x80, 0xB6, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x81, b"user1", None)).unwrap(),
        &mut st,
        &mut b,
    );
    let hash = [0x33u8; 32];
    let sig_r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x2A, 0x9E, 0x9A, &hash, Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((sig_r.sw1, sig_r.sw2), (0x90, 0x00));
    assert_eq!(sig_r.data.len(), 64);
    let pk_r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x81, 0xB6, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((pk_r.sw1, pk_r.sw2), (0x90, 0x00));
    let vk = VerifyingKey::from_bytes(pk_r.data.as_slice().try_into().unwrap()).expect("vk");
    let sig = Signature::from_bytes(sig_r.data.as_slice().try_into().unwrap());
    vk.verify_strict(&hash, &sig).expect("ed25519 verify");
}

#[test]
fn x25519_ecdh_returns_shared_secret() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut oid = HVec::new();
    for x in curve_oids::CURVE25519 {
        oid.push(*x).unwrap();
    }
    let c2 = AlgorithmAttributes::Ecdh { curve_oid: oid }
        .to_bytes()
        .unwrap();
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x83, b"adminadm", None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xDA, 0x00, 0xC2, c2.as_slice(), None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x80, 0xB8, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    let pk_r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x81, 0xB8, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((pk_r.sw1, pk_r.sw2), (0x90, 0x00));
    let card_pub_bytes: [u8; 32] = pk_r.data.as_slice().try_into().unwrap();
    let card_pub = X25519PublicKey::from(card_pub_bytes);
    let mut trng = FakeTrng::from_seed(0xE1CD_DA);
    let peer_sec = StaticSecret::random_from_rng(&mut trng);
    let peer_pub = X25519PublicKey::from(&peer_sec);
    let expected = peer_sec.diffie_hellman(&card_pub);
    let raw = apdu_hex(
        0x00,
        0x2A,
        0x80,
        0x86,
        &ecdh_command_data_x25519(peer_pub.as_bytes()),
        Some(0x00),
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x82, b"user1", None)).unwrap(),
        &mut st,
        &mut b,
    );
    let r = handle_apdu(&CommandApdu::parse(&raw).unwrap(), &mut st, &mut b);
    assert_eq!((r.sw1, r.sw2), (0x90, 0x00));
    assert_eq!(r.data.len(), 32);
    assert_eq!(r.data.as_slice(), expected.as_bytes());
}

#[test]
fn ed25519_key_survives_power_cycle() {
    let mut b = mk_openpgp_vault();
    init_vault_default_dos(&mut b.do_store);
    let mut oid = HVec::new();
    for x in curve_oids::ED25519 {
        oid.push(*x).unwrap();
    }
    let ed = AlgorithmAttributes::EdDsa { curve_oid: oid }
        .to_bytes()
        .unwrap();
    let mut st = CardState::new();
    let aid = build_aid(0x0000, [1, 2, 3, 4]);
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xA4, 0x04, 0x00, &aid, None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x83, b"adminadm", None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0xDA, 0x00, 0xC1, ed.as_slice(), None)).unwrap(),
        &mut st,
        &mut b,
    );
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x80, 0xB6, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    let pk1 = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x81, 0xB6, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((pk1.sw1, pk1.sw2), (0x90, 0x00));
    st.reset();
    b.load_private_keys().expect("reload keys");
    let pk2 = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x81, 0xB6, &[], Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!(pk1.data.as_slice(), pk2.data.as_slice());
    handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x81, b"user1", None)).unwrap(),
        &mut st,
        &mut b,
    );
    let hash = [0x77u8; 32];
    let sig_r = handle_apdu(
        &CommandApdu::parse(&apdu_hex(0x00, 0x2A, 0x9E, 0x9A, &hash, Some(0x00))).unwrap(),
        &mut st,
        &mut b,
    );
    assert_eq!((sig_r.sw1, sig_r.sw2), (0x90, 0x00));
    let vk = VerifyingKey::from_bytes(pk2.data.as_slice().try_into().unwrap()).expect("vk");
    let sig = Signature::from_bytes(sig_r.data.as_slice().try_into().unwrap());
    vk.verify_strict(&hash, &sig)
        .expect("ed25519 verify after reload");
}
