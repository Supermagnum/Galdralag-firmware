//! Vault-backed [`OpenPgpBackend`] for firmware integration.
//!
//! Composes [`DoStore`](super::do_store::DoStore) for persistent DOs, separate [`VaultStorage`] for
//! SHA-256 PIN verifier blobs, [`pin_policy::PinPolicyMachine`] for attempts, and `vault` Brainpool
//! material for PSO / ECDH / keygen.

#![deny(unsafe_code)]

use ed25519_dalek::Signer;
use galdr_core::hal::{HardwareTrng, MonotonicCounter, VaultStorage};
use galdr_vault::brainpool::{BrainpoolPublicKey, BrainpoolScalar};
use galdr_vault::ecdsa_brainpool::BrainpoolSigningKey;
use galdr_vault::sealed_key::SealedKeyBlob;
use galdr_vault::{
    KeyPurpose, SEALED_AUT_OFFSET, SEALED_BLOB_BYTES, SEALED_DEC_OFFSET, SEALED_SIG_OFFSET,
};
use heapless::Vec;
use pin_policy::{pin_compare, PinOutcome, PinPolicyConfig, PinPolicyMachine, ZeroisationTrigger};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use super::backend::{OpenPgpAudit, OpenPgpBackend, OpenPgpBackendError, OpenPgpKeySlot};
use super::do_store::DoStore;
use super::dos::{curve_oids, pin_bytes_to_verifier_digest, AlgorithmAttributes};
use super::error::StatusWord;

/// Zero-cost zeroisation hook when no policy FSM is wired.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopZeroise;

impl ZeroisationTrigger for NoopZeroise {
    fn trigger_zeroisation(&mut self) {}
}

/// OpenPGP card backend using RRAM [`VaultStorage`] for DOs and PIN hashes, plus in-memory key slots.
///
/// After a successful [`OpenPgpBackend::change_pin`], new [`PinPolicyMachine`] instances are built
/// using `new_user_counter` / `new_admin_counter` so attempt state matches a freshly provisioned
/// card (integrators must return cleared logical counters appropriate for their HAL).
pub struct OpenPgpVaultBackend<S, Sp, Sk, T, Cu, Ca, Zu, Za>
where
    S: VaultStorage,
    Sp: VaultStorage,
    Sk: VaultStorage,
    T: HardwareTrng,
    Cu: MonotonicCounter,
    Ca: MonotonicCounter,
    Zu: ZeroisationTrigger + Default,
    Za: ZeroisationTrigger + Default,
{
    /// Persistent DO storage (integrators may write defaults during provisioning).
    pub do_store: DoStore<S>,
    pin_storage: Sp,
    pin_user_off: u64,
    pin_admin_off: u64,
    key_storage: Sk,
    master_key: [u8; 32],
    trng: T,
    aid: [u8; 16],
    user_verifier: [u8; 32],
    admin_verifier: [u8; 32],
    user_machine: PinPolicyMachine<Zu>,
    admin_machine: PinPolicyMachine<Za>,
    user_counter: Cu,
    admin_counter: Ca,
    new_user_counter: fn() -> Cu,
    new_admin_counter: fn() -> Ca,
    sig_key: Option<BrainpoolSigningKey>,
    sig_ed25519: Option<ed25519_dalek::SigningKey>,
    aut_key: Option<BrainpoolSigningKey>,
    aut_ed25519: Option<ed25519_dalek::SigningKey>,
    dec_key: Option<BrainpoolScalar>,
    dec_x25519: Option<StaticSecret>,
    sig_counter: u32,
    termination: bool,
    audit: u32,
}

impl<S, Sp, Sk, T, Cu, Ca, Zu, Za> OpenPgpVaultBackend<S, Sp, Sk, T, Cu, Ca, Zu, Za>
where
    S: VaultStorage,
    Sp: VaultStorage,
    Sk: VaultStorage,
    T: HardwareTrng,
    Cu: MonotonicCounter,
    Ca: MonotonicCounter,
    Zu: ZeroisationTrigger + Default,
    Za: ZeroisationTrigger + Default,
{
    /// Build a backend: provisions PIN verifier blobs at `pin_user_off` / `pin_admin_off` on `pin_storage`,
    /// then loads sealed OpenPGP private keys from `key_storage`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        do_store: DoStore<S>,
        mut pin_storage: Sp,
        pin_user_off: u64,
        pin_admin_off: u64,
        key_storage: Sk,
        master_key: [u8; 32],
        trng: T,
        aid: [u8; 16],
        user_pin: &[u8],
        admin_pin: &[u8],
        user_machine: PinPolicyMachine<Zu>,
        admin_machine: PinPolicyMachine<Za>,
        user_counter: Cu,
        admin_counter: Ca,
        new_user_counter: fn() -> Cu,
        new_admin_counter: fn() -> Ca,
    ) -> Result<Self, galdr_core::HalError> {
        let uv = pin_bytes_to_verifier_digest(user_pin);
        let av = pin_bytes_to_verifier_digest(admin_pin);
        pin_storage.write(pin_user_off, &uv)?;
        pin_storage.write(pin_admin_off, &av)?;
        let mut s = Self {
            do_store,
            pin_storage,
            pin_user_off,
            pin_admin_off,
            key_storage,
            master_key,
            trng,
            aid,
            user_verifier: uv,
            admin_verifier: av,
            user_machine,
            admin_machine,
            user_counter,
            admin_counter,
            new_user_counter,
            new_admin_counter,
            sig_key: None,
            sig_ed25519: None,
            aut_key: None,
            aut_ed25519: None,
            dec_key: None,
            dec_x25519: None,
            sig_counter: 0,
            termination: false,
            audit: 0,
        };
        s.load_private_keys()?;
        Ok(s)
    }

    /// Open an already-provisioned card: read PIN verifier digests and sealed keys from storage.
    ///
    /// Unlike [`Self::new`], this does **not** write PIN hashes; use [`Self::new`] for first-time
    /// provisioning when firmware supplies initial PINs.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        do_store: DoStore<S>,
        pin_storage: Sp,
        pin_user_off: u64,
        pin_admin_off: u64,
        key_storage: Sk,
        master_key: [u8; 32],
        trng: T,
        aid: [u8; 16],
        user_machine: PinPolicyMachine<Zu>,
        admin_machine: PinPolicyMachine<Za>,
        user_counter: Cu,
        admin_counter: Ca,
        new_user_counter: fn() -> Cu,
        new_admin_counter: fn() -> Ca,
    ) -> Result<Self, galdr_core::HalError> {
        let mut s = Self {
            do_store,
            pin_storage,
            pin_user_off,
            pin_admin_off,
            key_storage,
            master_key,
            trng,
            aid,
            user_verifier: [0u8; 32],
            admin_verifier: [0u8; 32],
            user_machine,
            admin_machine,
            user_counter,
            admin_counter,
            new_user_counter,
            new_admin_counter,
            sig_key: None,
            sig_ed25519: None,
            aut_key: None,
            aut_ed25519: None,
            dec_key: None,
            dec_x25519: None,
            sig_counter: 0,
            termination: false,
            audit: 0,
        };
        s.load_pin_verifiers_from_storage()?;
        s.load_private_keys()?;
        Ok(s)
    }

    /// Same as [`Self::new`], but builds [`PinPolicyMachine`] instances from separate user and admin
    /// [`PinPolicyConfig`] values (e.g. different `max_attempts` for PW1 vs PW3).
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_policy(
        do_store: DoStore<S>,
        pin_storage: Sp,
        pin_user_off: u64,
        pin_admin_off: u64,
        key_storage: Sk,
        master_key: [u8; 32],
        trng: T,
        aid: [u8; 16],
        user_pin: &[u8],
        admin_pin: &[u8],
        user_policy: PinPolicyConfig,
        admin_policy: PinPolicyConfig,
        new_user_counter: fn() -> Cu,
        new_admin_counter: fn() -> Ca,
    ) -> Result<Self, galdr_core::HalError> {
        let user_machine = PinPolicyMachine::new(user_policy, Zu::default());
        let admin_machine = PinPolicyMachine::new(admin_policy, Za::default());
        Self::new(
            do_store,
            pin_storage,
            pin_user_off,
            pin_admin_off,
            key_storage,
            master_key,
            trng,
            aid,
            user_pin,
            admin_pin,
            user_machine,
            admin_machine,
            (new_user_counter)(),
            (new_admin_counter)(),
            new_user_counter,
            new_admin_counter,
        )
    }

    fn algorithm_attributes_for_slot(&self, slot: OpenPgpKeySlot) -> AlgorithmAttributes {
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
        let mut oid = Vec::new();
        for b in curve_oids::BRAINPOOL_P256R1 {
            oid.push(*b).unwrap();
        }
        match slot {
            OpenPgpKeySlot::Dec => AlgorithmAttributes::Ecdh { curve_oid: oid },
            _ => AlgorithmAttributes::Ecdsa { curve_oid: oid },
        }
    }

    /// Load sealed SIG / DEC / AUT keys from `key_storage`. Empty or invalid slots are skipped.
    pub fn load_private_keys(&mut self) -> Result<(), galdr_core::HalError> {
        self.sig_key = None;
        self.sig_ed25519 = None;
        self.aut_key = None;
        self.aut_ed25519 = None;
        self.dec_key = None;
        self.dec_x25519 = None;

        let mut buf = [0u8; SEALED_BLOB_BYTES];
        self.key_storage.read(SEALED_SIG_OFFSET as u64, &mut buf)?;
        let sig_attrs = self.algorithm_attributes_for_slot(OpenPgpKeySlot::Sig);
        if let Ok(v) =
            SealedKeyBlob::unseal_from_storage_cell(&buf, &self.master_key, KeyPurpose::OpenPgpSig)
        {
            let sl = v.as_slice();
            if sl.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(sl);
                match &sig_attrs {
                    AlgorithmAttributes::EdDsa { curve_oid }
                        if curve_oid.as_slice() == curve_oids::ED25519 =>
                    {
                        self.sig_ed25519 = Some(ed25519_dalek::SigningKey::from_bytes(&arr));
                    }
                    AlgorithmAttributes::Ecdsa { .. } => {
                        if let Ok(sk) = BrainpoolSigningKey::from_scalar_bytes_for_test(&arr) {
                            self.sig_key = Some(sk);
                        }
                    }
                    _ => {}
                }
            }
        }
        self.key_storage.read(SEALED_DEC_OFFSET as u64, &mut buf)?;
        let dec_attrs = self.algorithm_attributes_for_slot(OpenPgpKeySlot::Dec);
        if let Ok(v) =
            SealedKeyBlob::unseal_from_storage_cell(&buf, &self.master_key, KeyPurpose::OpenPgpDec)
        {
            let sl = v.as_slice();
            if sl.len() == 32 {
                match &dec_attrs {
                    AlgorithmAttributes::Ecdh { curve_oid }
                        if curve_oid.as_slice() == curve_oids::CURVE25519 =>
                    {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(sl);
                        self.dec_x25519 = Some(StaticSecret::from(a));
                    }
                    AlgorithmAttributes::Ecdh { .. } => {
                        if let Ok(sk) = BrainpoolScalar::from_secret_key_bytes_for_test(sl) {
                            self.dec_key = Some(sk);
                        }
                    }
                    _ => {}
                }
            }
        }
        self.key_storage.read(SEALED_AUT_OFFSET as u64, &mut buf)?;
        let aut_attrs = self.algorithm_attributes_for_slot(OpenPgpKeySlot::Aut);
        if let Ok(v) =
            SealedKeyBlob::unseal_from_storage_cell(&buf, &self.master_key, KeyPurpose::OpenPgpAut)
        {
            let sl = v.as_slice();
            if sl.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(sl);
                match &aut_attrs {
                    AlgorithmAttributes::EdDsa { curve_oid }
                        if curve_oid.as_slice() == curve_oids::ED25519 =>
                    {
                        self.aut_ed25519 = Some(ed25519_dalek::SigningKey::from_bytes(&arr));
                    }
                    AlgorithmAttributes::Ecdsa { .. } => {
                        if let Ok(sk) = BrainpoolSigningKey::from_scalar_bytes_for_test(&arr) {
                            self.aut_key = Some(sk);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn persist_private_key(
        &mut self,
        purpose: KeyPurpose,
        scalar_bytes: &[u8],
    ) -> Result<(), OpenPgpBackendError> {
        let blob = SealedKeyBlob::seal(&self.master_key, purpose, scalar_bytes, &mut self.trng)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::MemoryFailure))?;
        let off = match purpose {
            KeyPurpose::OpenPgpSig => SEALED_SIG_OFFSET as u64,
            KeyPurpose::OpenPgpDec => SEALED_DEC_OFFSET as u64,
            KeyPurpose::OpenPgpAut => SEALED_AUT_OFFSET as u64,
            _ => {
                return Err(OpenPgpBackendError::Status(StatusWord::IncorrectParameters));
            }
        };
        let mut cell = [0u8; SEALED_BLOB_BYTES];
        let sl = blob.as_slice();
        if sl.len() > SEALED_BLOB_BYTES {
            return Err(OpenPgpBackendError::Status(StatusWord::MemoryFailure));
        }
        cell[..sl.len()].copy_from_slice(sl);
        self.key_storage
            .write(off, &cell)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::MemoryFailure))?;
        Ok(())
    }

    /// Restore PIN hashes from `pin_storage` (e.g. after reboot). Fails if reads do not succeed.
    pub fn load_pin_verifiers_from_storage(&mut self) -> Result<(), galdr_core::HalError> {
        let mut uv = [0u8; 32];
        let mut av = [0u8; 32];
        self.pin_storage.read(self.pin_user_off, &mut uv)?;
        self.pin_storage.read(self.pin_admin_off, &mut av)?;
        self.user_verifier = uv;
        self.admin_verifier = av;
        Ok(())
    }

    fn persist_pin_hashes(&mut self) -> Result<(), OpenPgpBackendError> {
        self.pin_storage
            .write(self.pin_user_off, &self.user_verifier)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        self.pin_storage
            .write(self.pin_admin_off, &self.admin_verifier)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        Ok(())
    }

    fn ensure_not_terminated(&self) -> Result<(), OpenPgpBackendError> {
        if self.termination {
            return Err(OpenPgpBackendError::Status(StatusWord::TerminationState));
        }
        Ok(())
    }

    fn reset_user_machine(&mut self) {
        let cfg = self.user_machine.config;
        self.user_machine = PinPolicyMachine::new(cfg, Zu::default());
        self.user_counter = (self.new_user_counter)();
    }

    fn reset_admin_machine(&mut self) {
        let cfg = self.admin_machine.config;
        self.admin_machine = PinPolicyMachine::new(cfg, Za::default());
        self.admin_counter = (self.new_admin_counter)();
    }

    fn verify_user(&mut self, pin: &[u8]) -> Result<(), OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let d = pin_bytes_to_verifier_digest(pin);
        let exp = self.user_verifier;
        let r = self
            .user_machine
            .submit_attempt(&mut self.user_counter, || pin_compare(&d, &exp))
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
            .submit_attempt(&mut self.admin_counter, || pin_compare(&d, &exp))
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

impl<S, Sp, Sk, T, Cu, Ca, Zu, Za> OpenPgpAudit
    for OpenPgpVaultBackend<S, Sp, Sk, T, Cu, Ca, Zu, Za>
where
    S: VaultStorage,
    Sp: VaultStorage,
    Sk: VaultStorage,
    T: HardwareTrng,
    Cu: MonotonicCounter,
    Ca: MonotonicCounter,
    Zu: ZeroisationTrigger + Default,
    Za: ZeroisationTrigger + Default,
{
    fn log_event(&mut self, code: u32) {
        self.audit ^= code;
    }
}

impl<S, Sp, Sk, T, Cu, Ca, Zu, Za> OpenPgpBackend
    for OpenPgpVaultBackend<S, Sp, Sk, T, Cu, Ca, Zu, Za>
where
    S: VaultStorage,
    Sp: VaultStorage,
    Sk: VaultStorage,
    T: HardwareTrng,
    Cu: MonotonicCounter,
    Ca: MonotonicCounter,
    Zu: ZeroisationTrigger + Default,
    Za: ZeroisationTrigger + Default,
{
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
        self.ensure_not_terminated()?;
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

    fn get_do(&self, tag: u16) -> Result<Vec<u8, 512>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let mut out = Vec::new();
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
        self.algorithm_attributes_for_slot(slot)
    }

    fn pso_sign_hash(&mut self, hash: &[u8]) -> Result<Vec<u8, 512>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let sk = self.sig_key.as_ref().ok_or(OpenPgpBackendError::Status(
            StatusWord::ReferenceDataNotFound,
        ))?;
        let sig = sk
            .sign_handshake_sha256_prehash(hash, &mut self.trng)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        let mut out = Vec::new();
        for b in sig.der_bytes() {
            out.push(*b)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        }
        Ok(out)
    }

    fn pso_decipher(&mut self, _data: &[u8]) -> Result<Vec<u8, 512>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        Err(OpenPgpBackendError::Status(
            StatusWord::ReferenceDataNotFound,
        ))
    }

    fn ecdh_dec(
        &mut self,
        purpose: KeyPurpose,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8, 64>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        if purpose != KeyPurpose::OpenPgpDec {
            return Err(OpenPgpBackendError::Status(StatusWord::IncorrectParameters));
        }
        let sk = self.dec_key.as_ref().ok_or(OpenPgpBackendError::Status(
            StatusWord::ReferenceDataNotFound,
        ))?;
        let pk = BrainpoolPublicKey::from_sec1(peer_public_key)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::IncorrectParameters))?;
        let sec = sk
            .diffie_hellman(&pk)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        let mut out = Vec::new();
        for b in sec.as_bytes() {
            out.push(*b)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        }
        Ok(out)
    }

    fn get_challenge(&mut self, len: usize) -> Result<Vec<u8, 64>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let mut out = Vec::new();
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
        purpose: KeyPurpose,
        message: &[u8],
    ) -> Result<Vec<u8, 64>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let sk = match purpose {
            KeyPurpose::OpenPgpSig => self.sig_ed25519.as_ref(),
            KeyPurpose::OpenPgpAut => self.aut_ed25519.as_ref(),
            _ => None,
        }
        .ok_or(OpenPgpBackendError::Status(
            StatusWord::ReferenceDataNotFound,
        ))?;
        let sig = sk.sign(message);
        let mut out = Vec::new();
        for b in sig.to_bytes() {
            out.push(b)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        }
        Ok(out)
    }

    fn x25519_ecdh(
        &mut self,
        purpose: KeyPurpose,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8, 32>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        if purpose != KeyPurpose::OpenPgpDec {
            return Err(OpenPgpBackendError::Status(StatusWord::IncorrectParameters));
        }
        if peer_public_key.len() != 32 {
            return Err(OpenPgpBackendError::Status(StatusWord::IncorrectParameters));
        }
        let secret = self.dec_x25519.as_ref().ok_or(OpenPgpBackendError::Status(
            StatusWord::ReferenceDataNotFound,
        ))?;
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(peer_public_key);
        let peer = X25519PublicKey::from(pk_arr);
        let shared = secret.diffie_hellman(&peer);
        let mut out = Vec::new();
        for b in shared.to_bytes().iter() {
            out.push(*b)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        }
        Ok(out)
    }

    fn internal_authenticate(
        &mut self,
        challenge: &[u8],
    ) -> Result<Vec<u8, 512>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let attrs = self.algorithm_attributes_for_slot(OpenPgpKeySlot::Aut);
        if let AlgorithmAttributes::EdDsa { curve_oid } = &attrs {
            if curve_oid.as_slice() == curve_oids::ED25519 {
                let sk = self
                    .aut_ed25519
                    .as_ref()
                    .ok_or(OpenPgpBackendError::Status(
                        StatusWord::ReferenceDataNotFound,
                    ))?;
                let sig = sk.sign(challenge);
                let mut out = Vec::new();
                for b in sig.to_bytes() {
                    out.push(b)
                        .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                }
                return Ok(out);
            }
        }
        let sk = self.aut_key.as_ref().ok_or(OpenPgpBackendError::Status(
            StatusWord::ReferenceDataNotFound,
        ))?;
        let sig = sk
            .sign_handshake_sha256_prehash(challenge, &mut self.trng)
            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
        let mut out = Vec::new();
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
    ) -> Result<Vec<u8, 512>, OpenPgpBackendError> {
        self.ensure_not_terminated()?;
        let attrs = self.algorithm_attributes_for_slot(slot);

        if p1 == 0x81 {
            return match slot {
                OpenPgpKeySlot::Sig => match &attrs {
                    AlgorithmAttributes::EdDsa { curve_oid }
                        if curve_oid.as_slice() == curve_oids::ED25519 =>
                    {
                        let vk = self.sig_ed25519.as_ref().map(|k| k.verifying_key()).ok_or(
                            OpenPgpBackendError::Status(StatusWord::ReferenceDataNotFound),
                        )?;
                        let mut out = Vec::new();
                        for b in vk.as_bytes() {
                            out.push(*b).map_err(|_| {
                                OpenPgpBackendError::Status(StatusWord::ExecutionError)
                            })?;
                        }
                        Ok(out)
                    }
                    AlgorithmAttributes::Ecdsa { .. } => {
                        let vk = self.sig_key.as_ref().map(|k| k.verifying_key()).ok_or(
                            OpenPgpBackendError::Status(StatusWord::ReferenceDataNotFound),
                        )?;
                        let sec1 = vk.to_sec1_compressed();
                        let mut out = Vec::new();
                        for b in sec1 {
                            out.push(b).map_err(|_| {
                                OpenPgpBackendError::Status(StatusWord::ExecutionError)
                            })?;
                        }
                        Ok(out)
                    }
                    _ => Err(OpenPgpBackendError::Status(
                        StatusWord::ReferenceDataNotFound,
                    )),
                },
                OpenPgpKeySlot::Aut => match &attrs {
                    AlgorithmAttributes::EdDsa { curve_oid }
                        if curve_oid.as_slice() == curve_oids::ED25519 =>
                    {
                        let vk = self.aut_ed25519.as_ref().map(|k| k.verifying_key()).ok_or(
                            OpenPgpBackendError::Status(StatusWord::ReferenceDataNotFound),
                        )?;
                        let mut out = Vec::new();
                        for b in vk.as_bytes() {
                            out.push(*b).map_err(|_| {
                                OpenPgpBackendError::Status(StatusWord::ExecutionError)
                            })?;
                        }
                        Ok(out)
                    }
                    AlgorithmAttributes::Ecdsa { .. } => {
                        let vk = self.aut_key.as_ref().map(|k| k.verifying_key()).ok_or(
                            OpenPgpBackendError::Status(StatusWord::ReferenceDataNotFound),
                        )?;
                        let sec1 = vk.to_sec1_compressed();
                        let mut out = Vec::new();
                        for b in sec1 {
                            out.push(b).map_err(|_| {
                                OpenPgpBackendError::Status(StatusWord::ExecutionError)
                            })?;
                        }
                        Ok(out)
                    }
                    _ => Err(OpenPgpBackendError::Status(
                        StatusWord::ReferenceDataNotFound,
                    )),
                },
                OpenPgpKeySlot::Dec => match &attrs {
                    AlgorithmAttributes::Ecdh { curve_oid }
                        if curve_oid.as_slice() == curve_oids::CURVE25519 =>
                    {
                        let pk = self.dec_x25519.as_ref().map(X25519PublicKey::from).ok_or(
                            OpenPgpBackendError::Status(StatusWord::ReferenceDataNotFound),
                        )?;
                        let mut out = Vec::new();
                        for b in pk.as_bytes() {
                            out.push(*b).map_err(|_| {
                                OpenPgpBackendError::Status(StatusWord::ExecutionError)
                            })?;
                        }
                        Ok(out)
                    }
                    AlgorithmAttributes::Ecdh { .. } => {
                        let pk = self
                            .dec_key
                            .as_ref()
                            .and_then(|k| k.public_key().ok())
                            .ok_or(OpenPgpBackendError::Status(
                                StatusWord::ReferenceDataNotFound,
                            ))?;
                        let sec1 = pk.to_sec1_compressed();
                        let mut out = Vec::new();
                        for b in sec1 {
                            out.push(b).map_err(|_| {
                                OpenPgpBackendError::Status(StatusWord::ExecutionError)
                            })?;
                        }
                        Ok(out)
                    }
                    _ => Err(OpenPgpBackendError::Status(
                        StatusWord::ReferenceDataNotFound,
                    )),
                },
            };
        }
        if p1 != 0x80 {
            return Err(OpenPgpBackendError::Status(StatusWord::WrongParametersP1P2));
        }
        match slot {
            OpenPgpKeySlot::Sig => match &attrs {
                AlgorithmAttributes::EdDsa { curve_oid }
                    if curve_oid.as_slice() == curve_oids::ED25519 =>
                {
                    let signing_key = ed25519_dalek::SigningKey::generate(&mut self.trng);
                    let verifying_key = signing_key.verifying_key();
                    self.persist_private_key(KeyPurpose::OpenPgpSig, signing_key.as_bytes())?;
                    self.sig_key = None;
                    self.sig_ed25519 = Some(signing_key);
                    let mut out = Vec::new();
                    for b in verifying_key.as_bytes() {
                        out.push(*b)
                            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                    }
                    Ok(out)
                }
                AlgorithmAttributes::Ecdsa { .. } => {
                    let sk = BrainpoolSigningKey::generate(&mut self.trng)
                        .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                    let scalar = sk.to_scalar_bytes_for_test();
                    self.persist_private_key(KeyPurpose::OpenPgpSig, scalar.as_slice())?;
                    self.sig_ed25519 = None;
                    self.sig_key = Some(sk);
                    let vk = self.sig_key.as_ref().unwrap().verifying_key();
                    let sec1 = vk.to_sec1_compressed();
                    let mut out = Vec::new();
                    for b in sec1 {
                        out.push(b)
                            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                    }
                    Ok(out)
                }
                _ => Err(OpenPgpBackendError::Status(
                    StatusWord::ConditionsNotSatisfied,
                )),
            },
            OpenPgpKeySlot::Aut => match &attrs {
                AlgorithmAttributes::EdDsa { curve_oid }
                    if curve_oid.as_slice() == curve_oids::ED25519 =>
                {
                    let signing_key = ed25519_dalek::SigningKey::generate(&mut self.trng);
                    let verifying_key = signing_key.verifying_key();
                    self.persist_private_key(KeyPurpose::OpenPgpAut, signing_key.as_bytes())?;
                    self.aut_key = None;
                    self.aut_ed25519 = Some(signing_key);
                    let mut out = Vec::new();
                    for b in verifying_key.as_bytes() {
                        out.push(*b)
                            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                    }
                    Ok(out)
                }
                AlgorithmAttributes::Ecdsa { .. } => {
                    let sk = BrainpoolSigningKey::generate(&mut self.trng)
                        .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                    let scalar = sk.to_scalar_bytes_for_test();
                    self.persist_private_key(KeyPurpose::OpenPgpAut, scalar.as_slice())?;
                    self.aut_ed25519 = None;
                    self.aut_key = Some(sk);
                    let vk = self.aut_key.as_ref().unwrap().verifying_key();
                    let sec1 = vk.to_sec1_compressed();
                    let mut out = Vec::new();
                    for b in sec1 {
                        out.push(b)
                            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                    }
                    Ok(out)
                }
                _ => Err(OpenPgpBackendError::Status(
                    StatusWord::ConditionsNotSatisfied,
                )),
            },
            OpenPgpKeySlot::Dec => match &attrs {
                AlgorithmAttributes::Ecdh { curve_oid }
                    if curve_oid.as_slice() == curve_oids::CURVE25519 =>
                {
                    let secret = StaticSecret::random_from_rng(&mut self.trng);
                    let public = X25519PublicKey::from(&secret);
                    self.persist_private_key(KeyPurpose::OpenPgpDec, secret.as_bytes())?;
                    self.dec_key = None;
                    self.dec_x25519 = Some(secret);
                    let mut out = Vec::new();
                    for b in public.as_bytes() {
                        out.push(*b)
                            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                    }
                    Ok(out)
                }
                AlgorithmAttributes::Ecdh { .. } => {
                    let sk = BrainpoolScalar::generate(&mut self.trng)
                        .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                    let scalar = sk.to_secret_bytes_for_test();
                    self.persist_private_key(KeyPurpose::OpenPgpDec, scalar.as_slice())?;
                    self.dec_x25519 = None;
                    self.dec_key = Some(sk);
                    let vk = self
                        .dec_key
                        .as_ref()
                        .unwrap()
                        .public_key()
                        .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                    let sec1 = vk.to_sec1_compressed();
                    let mut out = Vec::new();
                    for b in sec1 {
                        out.push(b)
                            .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
                    }
                    Ok(out)
                }
                _ => Err(OpenPgpBackendError::Status(
                    StatusWord::ConditionsNotSatisfied,
                )),
            },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openpgp::aid::build_aid;
    use crate::openpgp::apdu::CommandApdu;
    use crate::openpgp::dispatch::handle_apdu;
    use crate::openpgp::do_store::DoStore;
    use crate::openpgp::dos::{curve_oids, AlgorithmAttributes};
    use crate::openpgp::state::CardState;
    use crate::openpgp::DO_STORE_REGION_BYTES;
    use galdr_core::fake_hal::{FakeMonotonicCounter, FakeTrng, FakeVaultStorage};
    use galdr_core::VaultStorage;
    use galdr_vault::brainpool::BrainpoolScalar;
    use pin_policy::PinPolicyConfig;

    #[derive(Default)]
    struct Z;

    impl ZeroisationTrigger for Z {
        fn trigger_zeroisation(&mut self) {}
    }

    fn apdu_hex(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: Option<u8>,
    ) -> std::vec::Vec<u8> {
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

    fn ecdh_command_data(peer_sec1: &[u8]) -> std::vec::Vec<u8> {
        let mut inner2 = std::vec::Vec::new();
        inner2.push(0x86);
        inner2.push(peer_sec1.len() as u8);
        inner2.extend_from_slice(peer_sec1);
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

    fn init_default_dos<S: VaultStorage>(do_store: &mut DoStore<S>) {
        let mut oid = Vec::new();
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

    fn mk_backend() -> OpenPgpVaultBackend<
        FakeVaultStorage,
        FakeVaultStorage,
        FakeVaultStorage,
        FakeTrng,
        FakeMonotonicCounter,
        FakeMonotonicCounter,
        Z,
        Z,
    > {
        let cfg = PinPolicyConfig::default();
        let do_store = DoStore::new(FakeVaultStorage::new(DO_STORE_REGION_BYTES), 0);
        let pin_store = FakeVaultStorage::new(64);
        let key_store = FakeVaultStorage::new(galdr_vault::SEALED_KEY_REGION_END);
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
            PinPolicyMachine::new(cfg, Z::default()),
            PinPolicyMachine::new(cfg, Z::default()),
            FakeMonotonicCounter::new(0),
            FakeMonotonicCounter::new(0),
            || FakeMonotonicCounter::new(0),
            || FakeMonotonicCounter::new(0),
        )
        .expect("backend new")
    }

    #[test]
    fn vault_backend_ecdh_matches_mock_semantics() {
        let mut b = mk_backend();
        init_default_dos(&mut b.do_store);
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
            &CommandApdu::parse(&apdu_hex(0x00, 0x47, 0x80, 0xB8, &[], Some(0x00))).unwrap(),
            &mut st,
            &mut b,
        );
        handle_apdu(
            &CommandApdu::parse(&apdu_hex(0x00, 0x20, 0x00, 0x82, b"user1", None)).unwrap(),
            &mut st,
            &mut b,
        );
        let mut trng = FakeTrng::from_seed(0xDEC0DE);
        let peer_sk = BrainpoolScalar::generate(&mut trng).expect("peer");
        let peer_pk = peer_sk.public_key().expect("pk");
        let card_pk = b.dec_key.as_ref().unwrap().public_key().expect("card pk");
        let expected = peer_sk
            .diffie_hellman(&card_pk)
            .expect("dh")
            .as_bytes()
            .to_vec();
        let raw = apdu_hex(
            0x00,
            0x2A,
            0x80,
            0x86,
            &ecdh_command_data(&peer_pk.to_sec1_uncompressed()),
            Some(0x00),
        );
        let r = handle_apdu(&CommandApdu::parse(&raw).unwrap(), &mut st, &mut b);
        assert_eq!((r.sw1, r.sw2), (0x90, 0x00));
        assert_eq!(r.data.len(), 32);
        assert_eq!(r.data.as_slice(), expected.as_slice());
    }
}
