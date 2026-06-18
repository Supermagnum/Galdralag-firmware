//! Xous-only RRAM / TRNG helpers for OpenPGP USB.

use core::convert::TryInto;

use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::OnceLock;

use bao1x_api::BOOT1_START;
use bao1x_hal::rram::Reram;
use galdr_core::hal::{MonotonicCounter, VaultStorage, ZeroiseController};
use galdr_core::HalError;
use pin_policy::{PinPolicyConfig, PinPolicyMachine, ZeroisationTrigger};
use rand_core::RngCore;
use trng::Trng;
use usb_personality::openpgp::do_store::DoStore;
use usb_personality::openpgp::vault_backend::OpenPgpVaultBackend;
use usb_personality::openpgp::DO_STORE_REGION_BYTES;
use utralib::HW_RERAM_MEM;
use galdr_vault::{derive_subkey_sha512, KeyPurpose};
use xous::MemoryFlags;

/// Region tag for [`ZeroiseController::zeroise_region`] / PIN breach handling.
const OPENPGP_ZEROISE_REGION_ID: u32 = 0x4F504700;

static PIN_ZEROISE: OnceLock<Rc<RefCell<BaochipVaultZeroise>>> = OnceLock::new();

/// Install the shared zeroisation target used by [`BaochipPinZeroise`] (call once before building [`OpenPgpVaultBackend`]).
pub fn init_pin_zeroise_singleton(z: Rc<RefCell<BaochipVaultZeroise>>) -> Result<(), ()> {
    PIN_ZEROISE.set(z).map_err(|_| ())
}

/// First byte offset into the on-chip RRAM array where [`Reram::write_slice`] accepts application data.
#[inline]
pub fn vault_phys_base() -> usize {
    BOOT1_START - HW_RERAM_MEM
}

/// Logical RRAM layout: OpenPGP DO store starts after the sealed-key sketch region (see `docs/RRAM_LAYOUT.md`).
const OPENPGP_DO_STORE_LOGICAL: u64 = 67_072;

#[inline]
fn pin_user_logical_off() -> u64 {
    OPENPGP_DO_STORE_LOGICAL + DO_STORE_REGION_BYTES as u64
}

#[inline]
fn pin_admin_logical_off() -> u64 {
    pin_user_logical_off() + 32
}

#[inline]
fn user_ctr_logical_off() -> u64 {
    pin_admin_logical_off() + 32
}

#[inline]
fn admin_ctr_logical_off() -> u64 {
    user_ctr_logical_off() + 4
}

#[inline]
fn master_record_logical_off() -> u64 {
    admin_ctr_logical_off() + 4
}

const OPENPGP_MASTER_MAGIC: &[u8; 4] = b"OGMK";
/// Magic + 32-byte persisted salt for [`load_or_derive_ccid_master_key`] (see `docs/RRAM_LAYOUT.md`).
pub const OPENPGP_MASTER_RECORD_BYTES: usize = 4 + 32;

/// Max raw PIN byte length per OpenPGP PW1/PW3 **stored in** the `PNU1` / `PNA1` RRAM provision slots.
///
/// OpenPGP card spec permits PW1 and PW3 up to **127** UTF-8 bytes each; this firmware uses a **37-byte**
/// on-disk record (`4` magic + `1` length byte + **`CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES`** payload), so
/// PINs longer than this constant **cannot** be persisted in the provision band and are rejected on write
/// (see [`load_or_provision_ccid_pin`] and [`open_or_provision_backend`]). Thirty-two bytes covers typical
/// numeric and passphrase-style PINs; raising the cap requires enlarging the slot and `openpgp_vault_logical_span_end()`.
pub const CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES: usize = 32;

/// On-disk record: `PNU1` / `PNA1` + length + up to [`CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES`] PIN bytes.
pub const CCID_PIN_PROVISION_SLOT_BYTES: usize = 4 + 1 + CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES;

const CCID_DEFAULT_PIN_DIGITS: usize = 8;

const _: () = assert!(CCID_DEFAULT_PIN_DIGITS <= CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES);
const _: () = assert!(CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES <= 127);

const CCID_PINPROV_USER_MAGIC: &[u8; 4] = b"PNU1";
const CCID_PINPROV_ADMIN_MAGIC: &[u8; 4] = b"PNA1";

#[inline]
fn pin_provision_user_logical_off() -> u64 {
    master_record_logical_off() + OPENPGP_MASTER_RECORD_BYTES as u64
}

#[inline]
fn pin_provision_admin_logical_off() -> u64 {
    pin_provision_user_logical_off() + CCID_PIN_PROVISION_SLOT_BYTES as u64
}

/// Span from RRAM logical byte 0 through CCID pin provision records; used for wipe and `map_memory`.
#[inline]
pub fn openpgp_vault_logical_span_end() -> usize {
    (pin_provision_admin_logical_off() + CCID_PIN_PROVISION_SLOT_BYTES as u64) as usize
}

/// Map the contiguous RRAM window that covers all OpenPGP-relative offsets `0..openpgp_vault_logical_span_end()`.
pub fn map_openpgp_rram_windows(reram: &mut Pin<Box<Reram>>) -> Result<(), xous::Error> {
    let base = vault_phys_base();
    let end = base + openpgp_vault_logical_span_end();
    let page_base = base & !0xFFF;
    let page_end = (end + 0xFFF) & !0xFFF;
    let len = page_end - page_base;
    let phys_addr = HW_RERAM_MEM + page_base;
    let r = xous::syscall::map_memory(
        xous::MemoryAddress::new(phys_addr),
        None,
        len,
        MemoryFlags::R | MemoryFlags::W,
    )?;
    reram.add_range(page_base, r);
    Ok(())
}

fn rram_read_bytes(rram: &Reram, mut phys: usize, out: &mut [u8]) -> Result<(), HalError> {
    let mut o = 0;
    while o < out.len() {
        let slab = rram.array(phys).map_err(|_| HalError::Bus)?;
        let take = (out.len() - o).min(slab.len());
        out[o..o + take].copy_from_slice(&slab[..take]);
        o += take;
        phys += take;
    }
    Ok(())
}

fn zero_rram_window(rram: &mut Reram, phys_base: usize, span: usize) -> Result<(), HalError> {
    let mut buf = [0u8; 256];
    let mut pos = 0usize;
    while pos < span {
        let n = (span - pos).min(buf.len());
        rram
            .write_slice(phys_base + pos, &buf[..n])
            .map_err(|_| HalError::Bus)?;
        pos += n;
    }
    Ok(())
}

/// Shared RRAM accessor for [`VaultStorage`]; `offset` is the logical vault byte index (same as `vault` layout constants).
#[derive(Clone)]
pub struct RramVaultStorage {
    rram: Rc<RefCell<Pin<Box<Reram>>>>,
    phys_base: usize,
}

impl VaultStorage for RramVaultStorage {
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), HalError> {
        let add = usize::try_from(offset).map_err(|_| HalError::Bus)?;
        let phys = self.phys_base.checked_add(add).ok_or(HalError::Bus)?;
        let r = self.rram.borrow();
        rram_read_bytes(&*r, phys, out)
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), HalError> {
        let add = usize::try_from(offset).map_err(|_| HalError::Bus)?;
        let phys = self.phys_base.checked_add(add).ok_or(HalError::Bus)?;
        let mut r = self.rram.borrow_mut();
        r.write_slice(phys, data).map_err(|_| HalError::Bus)?;
        Ok(())
    }
}

/// Persistent attempt counter in RRAM (one u32 little-endian cell).
pub struct RramMonotonicCounter {
    rram: Rc<RefCell<Pin<Box<Reram>>>>,
    phys: usize,
}

impl MonotonicCounter for RramMonotonicCounter {
    fn read(&self) -> Result<u32, HalError> {
        let mut b = [0u8; 4];
        let r = self.rram.borrow();
        rram_read_bytes(&*r, self.phys, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn increment(&mut self) -> Result<u32, HalError> {
        let v = <Self as MonotonicCounter>::read(self)?.saturating_add(1);
        let b = v.to_le_bytes();
        let mut r = self.rram.borrow_mut();
        r.write_slice(self.phys, &b).map_err(|_| HalError::Bus)?;
        Ok(v)
    }

    fn refund_on_success(&mut self) -> Result<(), HalError> {
        let v = <Self as MonotonicCounter>::read(self)?;
        let v = v.saturating_sub(1);
        let b = v.to_le_bytes();
        let mut r = self.rram.borrow_mut();
        r.write_slice(self.phys, &b).map_err(|_| HalError::Bus)?;
        Ok(())
    }
}

/// Active wipe of the OpenPGP vault window (TRNG passes belong in platform boot; here we zero host-visible secrets).
pub struct BaochipVaultZeroise {
    rram: Rc<RefCell<Pin<Box<Reram>>>>,
    phys_base: usize,
    span: usize,
}

impl BaochipVaultZeroise {
    pub fn new(rram: Rc<RefCell<Pin<Box<Reram>>>>, phys_base: usize, span: usize) -> Self {
        Self { rram, phys_base, span }
    }
}

impl ZeroiseController for BaochipVaultZeroise {
    fn zeroise_region(&mut self, region_id: u32) -> Result<(), HalError> {
        if region_id != OPENPGP_ZEROISE_REGION_ID {
            return Err(HalError::Denied);
        }
        let mut r = self.rram.borrow_mut();
        zero_rram_window(&mut *r, self.phys_base, self.span)
    }
}

/// PIN-policy hook into [`BaochipVaultZeroise`] (requires [`init_pin_zeroise_singleton`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct BaochipPinZeroise;

impl ZeroisationTrigger for BaochipPinZeroise {
    fn trigger_zeroisation(&mut self) {
        if let Some(z) = PIN_ZEROISE.get() {
            let _ = z.borrow_mut().zeroise_region(OPENPGP_ZEROISE_REGION_ID);
        }
    }
}

pub type BaochipVaultBackend = OpenPgpVaultBackend<
    RramVaultStorage,
    RramVaultStorage,
    RramVaultStorage,
    Trng,
    RramMonotonicCounter,
    RramMonotonicCounter,
    BaochipPinZeroise,
    BaochipPinZeroise,
>;

/// Persisted salt at logical offset [`master_record_logical_off`], then HKDF-SHA512 with
/// [`galdr_vault::KeyPurpose::OpenPgpCcidMaster`]: IKM = salt || `device_binding`, empty HKDF salt.
/// First boot creates salt with `trng`.
pub fn load_or_derive_ccid_master_key(
    rram: &Rc<RefCell<Pin<Box<Reram>>>>,
    trng: &mut Trng,
    device_binding: &[u8],
) -> Result<[u8; 32], HalError> {
    let p_base = vault_phys_base();
    let phys = p_base + master_record_logical_off() as usize;
    let mut record = [0u8; OPENPGP_MASTER_RECORD_BYTES];
    {
        let r = rram.borrow();
        rram_read_bytes(&*r, phys, &mut record)?;
    }
    if &record[..4] != OPENPGP_MASTER_MAGIC.as_slice() {
        let mut salt = [0u8; 32];
        trng.fill_bytes(&mut salt);
        record[..4].copy_from_slice(OPENPGP_MASTER_MAGIC.as_slice());
        record[4..].copy_from_slice(&salt);
        let mut w = rram.borrow_mut();
        w.write_slice(phys, &record).map_err(|_| HalError::Bus)?;
    }
    let salt = &record[4..];
    let mut ikm = std::vec::Vec::with_capacity(32 + device_binding.len());
    ikm.extend_from_slice(salt);
    ikm.extend_from_slice(device_binding);
    let mut mk = [0u8; 32];
    derive_subkey_sha512(&ikm, &[], KeyPurpose::OpenPgpCcidMaster, &mut mk).map_err(|_| HalError::Bus)?;
    Ok(mk)
}

#[cfg(feature = "dev-provisioning")]
/// Read `OPENPGP_MASTER_KEY_HEX` (64 hex chars). **Not for production tokens.**
pub fn master_key_dev_from_env() -> Result<[u8; 32], ()> {
    let s = std::env::var("OPENPGP_MASTER_KEY_HEX").map_err(|_| ())?;
    master_key_from_hex64(s.trim())
}

/// Decode 64 hex characters into a 32-byte AEAD master key (for **`dev-provisioning` only**).
pub fn master_key_from_hex64(s: &str) -> Result<[u8; 32], ()> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(());
    }
    fn hi(c: u8) -> Result<u8, ()> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(10 + c - b'a'),
            b'A'..=b'F' => Ok(10 + c - b'A'),
            _ => Err(()),
        }
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi_n = hi(b[i * 2])?;
        let lo_n = hi(b[i * 2 + 1])?;
        out[i] = hi_n << 4 | lo_n;
    }
    Ok(out)
}

fn clear_ccid_pin_provision_slots(rram: &Rc<RefCell<Pin<Box<Reram>>>>, p_base: usize) -> Result<(), HalError> {
    let u = p_base + pin_provision_user_logical_off() as usize;
    let a = p_base + pin_provision_admin_logical_off() as usize;
    let mut w = rram.borrow_mut();
    zero_rram_window(&mut *w, u, CCID_PIN_PROVISION_SLOT_BYTES)?;
    zero_rram_window(&mut *w, a, CCID_PIN_PROVISION_SLOT_BYTES)?;
    Ok(())
}

fn pin_provision_record_valid(rram: &Rc<RefCell<Pin<Box<Reram>>>>, magic: &[u8; 4], logical_off: u64) -> bool {
    let p_base = vault_phys_base();
    let phys = p_base + logical_off as usize;
    let mut buf = [0u8; CCID_PIN_PROVISION_SLOT_BYTES];
    let r = rram.borrow();
    if rram_read_bytes(&*r, phys, &mut buf).is_err() {
        return false;
    }
    if buf[..4] != *magic {
        return false;
    }
    let n = buf[4] as usize;
    !(n == 0 || n > CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES)
}

/// `true` when both `PNU1` and `PNA1` hold well-formed provision records (magic, length, payload).
pub fn provision_slots_have_valid_pins(rram: &Rc<RefCell<Pin<Box<Reram>>>>) -> bool {
    pin_provision_record_valid(rram, CCID_PINPROV_USER_MAGIC, pin_provision_user_logical_off())
        && pin_provision_record_valid(rram, CCID_PINPROV_ADMIN_MAGIC, pin_provision_admin_logical_off())
}

/// Write operator-chosen pins into `PNU1` / `PNA1` before [`open_or_provision_backend`] consumes them.
pub fn write_provisioning_pins(
    rram: &Rc<RefCell<Pin<Box<Reram>>>>,
    user_pin: &[u8],
    admin_pin: &[u8],
) -> Result<(), HalError> {
    if user_pin.is_empty() || user_pin.len() > CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES {
        return Err(HalError::Denied);
    }
    if admin_pin.is_empty() || admin_pin.len() > CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES {
        return Err(HalError::Denied);
    }
    let p_base = vault_phys_base();
    let u = p_base + pin_provision_user_logical_off() as usize;
    let a = p_base + pin_provision_admin_logical_off() as usize;
    let mut rec_u = [0u8; CCID_PIN_PROVISION_SLOT_BYTES];
    rec_u[..4].copy_from_slice(CCID_PINPROV_USER_MAGIC.as_slice());
    rec_u[4] = user_pin.len() as u8;
    rec_u[5..5 + user_pin.len()].copy_from_slice(user_pin);
    let mut rec_a = [0u8; CCID_PIN_PROVISION_SLOT_BYTES];
    rec_a[..4].copy_from_slice(CCID_PINPROV_ADMIN_MAGIC.as_slice());
    rec_a[4] = admin_pin.len() as u8;
    rec_a[5..5 + admin_pin.len()].copy_from_slice(admin_pin);
    let mut w = rram.borrow_mut();
    w.write_slice(u, &rec_u).map_err(|_| HalError::Bus)?;
    w.write_slice(a, &rec_a).map_err(|_| HalError::Bus)?;
    Ok(())
}

fn load_or_provision_ccid_pin(
    rram: &Rc<RefCell<Pin<Box<Reram>>>>,
    magic: &[u8; 4],
    logical_off: u64,
    trng: &mut Trng,
) -> Result<Vec<u8>, HalError> {
    let p_base = vault_phys_base();
    let phys = p_base + logical_off as usize;
    let mut buf = [0u8; CCID_PIN_PROVISION_SLOT_BYTES];
    {
        let r = rram.borrow();
        rram_read_bytes(&*r, phys, &mut buf)?;
    }
    if buf[..4] == *magic {
        let n = buf[4] as usize;
        if n == 0 || n > CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES {
            return Err(HalError::Denied);
        }
        return Ok(buf[5..5 + n].to_vec());
    }
    #[cfg(feature = "trng-pin-fallback")]
    {
        // NOT FOR PRODUCTION — PIN is unrecoverable unless captured out-of-band.
        let mut pin = vec![0u8; CCID_DEFAULT_PIN_DIGITS];
        for p in pin.iter_mut() {
            *p = b'0' + (trng.next_u32() % 10) as u8;
        }
        let mut rec = [0u8; CCID_PIN_PROVISION_SLOT_BYTES];
        rec[..4].copy_from_slice(magic.as_slice());
        rec[4] = pin.len() as u8;
        rec[5..5 + pin.len()].copy_from_slice(&pin);
        let mut w = rram.borrow_mut();
        w.write_slice(phys, &rec).map_err(|_| HalError::Bus)?;
        Ok(pin)
    }
    #[cfg(not(feature = "trng-pin-fallback"))]
    {
        let _ = trng;
        Err(HalError::NeedsProvisioning)
    }
}

/// `true` if either OpenPGP PIN verifier cell is still all zero (needs [`OpenPgpVaultBackend::new`]).
pub fn ccid_pin_hashes_unprovisioned(rram: &Rc<RefCell<Pin<Box<Reram>>>>) -> bool {
    let p_base = vault_phys_base();
    let r = rram.borrow();
    let pin_u = p_base + pin_user_logical_off() as usize;
    let pin_a = p_base + pin_admin_logical_off() as usize;
    pin_digest_unprovisioned(&*r, pin_u) || pin_digest_unprovisioned(&*r, pin_a)
}

/// Load initial user PIN from `PNU1`, or TRNG-provision it when `trng-pin-fallback` is enabled,
/// or return [`HalError::NeedsProvisioning`] when the slot is empty (production: use USB CDC provisioning first).
pub fn load_or_provision_ccid_user_pin_bytes(
    rram: &Rc<RefCell<Pin<Box<Reram>>>>,
    trng: &mut Trng,
) -> Result<Vec<u8>, HalError> {
    load_or_provision_ccid_pin(rram, CCID_PINPROV_USER_MAGIC, pin_provision_user_logical_off(), trng)
}

/// Load initial admin PIN from `PNA1`, or TRNG-provision when `trng-pin-fallback` is enabled,
/// or return [`HalError::NeedsProvisioning`] when the slot is empty.
pub fn load_or_provision_ccid_admin_pin_bytes(
    rram: &Rc<RefCell<Pin<Box<Reram>>>>,
    trng: &mut Trng,
) -> Result<Vec<u8>, HalError> {
    load_or_provision_ccid_pin(rram, CCID_PINPROV_ADMIN_MAGIC, pin_provision_admin_logical_off(), trng)
}

#[cfg(feature = "dev-provisioning")]
fn validate_ccid_pin_env(s: &str) -> Result<Vec<u8>, ()> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES {
        return Err(());
    }
    Ok(b.to_vec())
}

/// Read `CCID_USER_PIN` / `CCID_ADMIN_PIN` (UTF-8, byte length `1..=CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES`). **Development builds only.**
#[cfg(feature = "dev-provisioning")]
pub fn ccid_pins_dev_from_env() -> Result<(Vec<u8>, Vec<u8>), ()> {
    let u = validate_ccid_pin_env(std::env::var("CCID_USER_PIN").map_err(|_| ())?.trim())?;
    let a = validate_ccid_pin_env(std::env::var("CCID_ADMIN_PIN").map_err(|_| ())?.trim())?;
    Ok((u, a))
}

fn pin_digest_unprovisioned(rram: &Reram, phys: usize) -> bool {
    let mut buf = [0u8; 32];
    if rram_read_bytes(rram, phys, &mut buf).is_err() {
        return true;
    }
    buf.iter().all(|&x| x == 0)
}

/// Build backend: [`OpenPgpVaultBackend::open`] when PIN hashes exist; otherwise [`OpenPgpVaultBackend::new`] for first boot.
#[allow(clippy::too_many_arguments)]
pub fn open_or_provision_backend(
    rram: Rc<RefCell<Pin<Box<Reram>>>>,
    xns: &xous_names::XousNames,
    master_key: [u8; 32],
    aid: [u8; 16],
    user_pin: &[u8],
    admin_pin: &[u8],
) -> Result<BaochipVaultBackend, HalError> {
    let p_base = vault_phys_base();
    let vz = Rc::new(RefCell::new(BaochipVaultZeroise::new(
        rram.clone(),
        p_base,
        openpgp_vault_logical_span_end(),
    )));
    init_pin_zeroise_singleton(vz).map_err(|_| HalError::Bus)?;

    let vs = RramVaultStorage {
        rram: rram.clone(),
        phys_base: p_base,
    };
    let do_store = DoStore::new(vs.clone(), OPENPGP_DO_STORE_LOGICAL);
    let pin_u = p_base + pin_user_logical_off() as usize;
    let pin_a = p_base + pin_admin_logical_off() as usize;
    let user_unprov = pin_digest_unprovisioned(&*rram.borrow(), pin_u);
    let admin_unprov = pin_digest_unprovisioned(&*rram.borrow(), pin_a);
    let trng = Trng::new(xns).map_err(|_| HalError::Bus)?;
    let cfg = PinPolicyConfig::default();
    let u_ctr_phys = p_base + user_ctr_logical_off() as usize;
    let a_ctr_phys = p_base + admin_ctr_logical_off() as usize;

    let new_user = || RramMonotonicCounter {
        rram: rram.clone(),
        phys: u_ctr_phys,
    };
    let new_admin = || RramMonotonicCounter {
        rram: rram.clone(),
        phys: a_ctr_phys,
    };

    if user_unprov || admin_unprov {
        #[cfg(not(feature = "dev-provisioning"))]
        {
            #[cfg(not(feature = "trng-pin-fallback"))]
            {
                if !provision_slots_have_valid_pins(&rram) {
                    return Err(HalError::NeedsProvisioning);
                }
            }
        }
        if user_pin.len() > CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES || admin_pin.len() > CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES
        {
            return Err(HalError::Denied);
        }
        let backend = OpenPgpVaultBackend::new(
            do_store,
            vs.clone(),
            pin_user_logical_off(),
            pin_admin_logical_off(),
            vs.clone(),
            master_key,
            trng,
            aid,
            user_pin,
            admin_pin,
            PinPolicyMachine::new(cfg, new_user(), BaochipPinZeroise),
            PinPolicyMachine::new(cfg, new_admin(), BaochipPinZeroise),
            || RramMonotonicCounter {
                rram: rram.clone(),
                phys: u_ctr_phys,
            },
            || RramMonotonicCounter {
                rram: rram.clone(),
                phys: a_ctr_phys,
            },
        )?;
        clear_ccid_pin_provision_slots(&rram, p_base)?;
        Ok(backend)
    } else {
        OpenPgpVaultBackend::open(
            do_store,
            vs.clone(),
            pin_user_logical_off(),
            pin_admin_logical_off(),
            vs.clone(),
            master_key,
            trng,
            aid,
            PinPolicyMachine::new(cfg, new_user(), BaochipPinZeroise),
            PinPolicyMachine::new(cfg, new_admin(), BaochipPinZeroise),
            || RramMonotonicCounter {
                rram: rram.clone(),
                phys: u_ctr_phys,
            },
            || RramMonotonicCounter {
                rram: rram.clone(),
                phys: a_ctr_phys,
            },
        )
    }
}
