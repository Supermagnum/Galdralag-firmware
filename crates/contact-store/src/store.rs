//! [`ContactStore`] CRUD, integrity gate, and PIN-gated key unwrap.

use crate::error::ContactStoreError;
use crate::heap::StringHeap;
use crate::index::ContactIndex;
use crate::key_region::KeyMaterialRegion;
use crate::layout::{
    CONTACT_RECORD_ARRAY_OFFSET, CONTACT_RECORD_BYTES, CONTACT_SLOT_COUNT,
    CONTACT_STORE_INTEGRITY_OFFSET, CONTACT_STORE_PROVISION_MARKER_OFFSET,
    KEY_REGION_BYTES, KEY_REGION_OFFSET,
    MAX_PUBLIC_KEY_BYTES, MAX_STRING_FIELD_BYTES, RECIPIENT_SLOT_COUNT, RECIPIENT_SLOT_START,
    STRING_HEAP_BYTES, STRING_HEAP_OFFSET, TIMING_LOG_BYTES, TIMING_LOG_OFFSET,
};
use crate::timing_log::TimingLogEntry;
use crate::record::{
    field, field_source_set, ContactFlags, ContactRecord, FieldSource, KeyAlgo, PinBuffer,
    PublicKeyBlob, StringRef,
};
use crate::layout::CONTACT_RECORD_MAGIC;
use crate::timing_log::TimingLog;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use galdr_core::hal::{MonotonicCounter, VaultStorage};
use galdr_vault::kdf_policy::{derive_subkey_sha512, KeyPurpose};
use pin_policy::{pin_compare, PinOutcome, PinPolicyMachine, ZeroisationTrigger};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// RRAM slot index (`0..=53`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotIndex(pub u8);

impl SlotIndex {
    fn from_u8(v: u8) -> Result<Self, ContactStoreError> {
        if v >= CONTACT_SLOT_COUNT as u8 {
            return Err(ContactStoreError::InvalidSlot);
        }
        Ok(Self(v))
    }
}

/// Input for creating a contact.
pub struct NewContact<'a> {
    /// OpenPGP fingerprint.
    pub fingerprint: [u8; 32],
    /// Optional callsign (NUL-padded to 12 bytes).
    pub callsign: [u8; 12],
    /// DMR id (`0` = absent).
    pub dmr_id: u32,
    /// Public-key algorithm.
    pub key_algo: KeyAlgo,
    /// Public key bytes (plaintext or PIN-wrapped ciphertext).
    pub public_key: &'a [u8],
    /// E-mail UTF-8.
    pub email: &'a [u8],
    /// Display name UTF-8 (optional).
    pub display_name: Option<&'a [u8]>,
    /// True for own-identity slots (`0..=3`).
    pub own_identity: bool,
    /// PIN-protected key storage.
    pub pin_protected: bool,
    /// PIN verifier digest (32 bytes) when `pin_protected`.
    pub pin_verifier: Option<[u8; 32]>,
    /// AES-GCM nonce/tag when storing wrapped key bytes.
    pub pin_nonce: Option<[u8; 12]>,
    pub pin_tag: Option<[u8; 16]>,
}

/// Partial update for an existing record.
pub struct ContactUpdate<'a> {
    /// Replace callsign.
    pub callsign: Option<[u8; 12]>,
    /// Replace DMR id.
    pub dmr_id: Option<u32>,
    /// Replace e-mail string.
    pub email: Option<&'a [u8]>,
    /// Replace display name.
    pub display_name: Option<&'a [u8]>,
    /// Replace `last_fetched`.
    pub last_fetched: Option<u32>,
    /// Update STALE flag.
    pub stale: Option<bool>,
}

/// Iterator over occupied `(slot, fingerprint)` pairs.
pub struct ContactListIter {
    items: [(u8, [u8; 32]); 54],
    len: u8,
    pos: u8,
}

impl Iterator for ContactListIter {
    type Item = Result<(SlotIndex, [u8; 32]), ContactStoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        let n = usize::from(self.pos);
        if n >= usize::from(self.len) {
            return None;
        }
        let (slot, fp) = self.items[n];
        self.pos += 1;
        Some(SlotIndex::from_u8(slot).map(|s| (s, fp)))
    }
}

/// On-chip contact directory with integrity gate.
pub struct ContactStore<S, C> {
    storage: S,
    counter: C,
    index: ContactIndex,
    integrity_gate: bool,
    integrity_register: [u8; 32],
    master_key: [u8; 32],
    string_heap: StringHeap,
    key_region: KeyMaterialRegion,
    /// Append-only timing log for deferred `last_fetched` updates.
    pub timing_log: TimingLog,
}

impl<S: VaultStorage, C: MonotonicCounter> ContactStore<S, C> {
    /// Construct in the pre-integrity-check state (does not read RRAM).
    pub fn new(storage: S, counter: C, master_key: [u8; 32]) -> Self {
        Self {
            storage,
            counter,
            index: ContactIndex::new(),
            integrity_gate: false,
            integrity_register: [0u8; 32],
            master_key,
            string_heap: StringHeap::new(),
            key_region: KeyMaterialRegion::new(),
            timing_log: TimingLog::new(),
        }
    }

    fn read_provision_marker(&self) -> Result<u32, ContactStoreError> {
        let mut buf = [0u8; 4];
        self.storage
            .read(CONTACT_STORE_PROVISION_MARKER_OFFSET, &mut buf)
            .map_err(|_| ContactStoreError::StorageRead)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn write_provision_marker(&mut self, value: u32) -> Result<(), ContactStoreError> {
        self.storage
            .write(
                CONTACT_STORE_PROVISION_MARKER_OFFSET,
                &value.to_le_bytes(),
            )
            .map_err(|_| ContactStoreError::StorageWrite)
    }

    fn load_integrity_register(&mut self) -> Result<(), ContactStoreError> {
        self.storage
            .read(
                CONTACT_STORE_INTEGRITY_OFFSET,
                &mut self.integrity_register,
            )
            .map_err(|_| ContactStoreError::StorageRead)
    }

    fn persist_integrity_register(&mut self) -> Result<(), ContactStoreError> {
        self.storage
            .write(
                CONTACT_STORE_INTEGRITY_OFFSET,
                &self.integrity_register,
            )
            .map_err(|_| ContactStoreError::StorageWrite)
    }

    fn zero_region(&mut self, offset: u64, len: usize) -> Result<(), ContactStoreError> {
        let zeros = [0u8; 256];
        let mut remaining = len;
        let mut pos = offset;
        while remaining > 0 {
            let chunk = remaining.min(zeros.len());
            self.storage
                .write(pos, &zeros[..chunk])
                .map_err(|_| ContactStoreError::StorageWrite)?;
            pos += chunk as u64;
            remaining -= chunk;
        }
        Ok(())
    }

    /// Factory-fresh provisioning: zero RRAM band, write integrity digest and provision marker.
    ///
    /// On silicon, `counter` must map to always-on slot
    /// [`crate::CONTACT_STORE_PROVISION_COUNTER`] (see `docs/RRAM_LAYOUT.md`).
    pub fn provision_fresh(&mut self, counter: &mut C) -> Result<(), ContactStoreError> {
        self.load_integrity_register()?;
        if !self.integrity_register.iter().all(|&b| b == 0) {
            return Err(ContactStoreError::AlreadyProvisioned);
        }
        if self.read_provision_marker()? != 0 {
            return Err(ContactStoreError::AlreadyProvisioned);
        }
        for slot in 0..CONTACT_SLOT_COUNT as u8 {
            self.write_record(slot, &ContactRecord::default())?;
        }
        self.zero_region(STRING_HEAP_OFFSET, STRING_HEAP_BYTES as usize)?;
        self.zero_region(KEY_REGION_OFFSET, KEY_REGION_BYTES as usize)?;
        self.zero_region(TIMING_LOG_OFFSET, TIMING_LOG_BYTES as usize)?;
        self.string_heap = StringHeap::new();
        self.key_region = KeyMaterialRegion::new();
        self.timing_log = TimingLog::new();
        self.index = ContactIndex::new();
        self.integrity_register = self.compute_integrity_digest()?;
        self.persist_integrity_register()?;
        // Records provisioning on always-on counter slot [`CONTACT_STORE_PROVISION_COUNTER`] (7).
        counter
            .increment()
            .map_err(|_| ContactStoreError::CounterError)?;
        self.write_provision_marker(1)?;
        self.integrity_gate = true;
        Ok(())
    }

    fn gate(&self) -> Result<(), ContactStoreError> {
        if !self.integrity_gate {
            return Err(ContactStoreError::NotInitialised);
        }
        Ok(())
    }

    fn record_offset(slot: u8) -> u64 {
        CONTACT_RECORD_ARRAY_OFFSET + u64::from(slot) * CONTACT_RECORD_BYTES as u64
    }

    fn read_record(&self, slot: u8) -> Result<ContactRecord, ContactStoreError> {
        let mut buf = [0u8; CONTACT_RECORD_BYTES];
        self.storage
            .read(Self::record_offset(slot), &mut buf)
            .map_err(|_| ContactStoreError::StorageRead)?;
        if buf[0..4] != CONTACT_RECORD_MAGIC.to_le_bytes() {
            return Ok(ContactRecord::default());
        }
        ContactRecord::from_bytes_verified(&buf)
    }

    fn write_record(&mut self, slot: u8, rec: &ContactRecord) -> Result<(), ContactStoreError> {
        let bytes = rec.as_bytes();
        self.storage
            .write(Self::record_offset(slot), &bytes)
            .map_err(|_| ContactStoreError::StorageWrite)
    }

    fn scan_bumps(records: &[ContactRecord; 54]) -> (u32, u32) {
        let mut heap_bump = 0u32;
        let mut key_bump = 0u32;
        for rec in records {
            if !rec.is_active() {
                continue;
            }
            for r in [
                rec.email,
                rec.display_name,
                rec.badge_number,
                rec.organisation,
                rec.department,
                rec.role,
                rec.note,
                rec.radio_affiliation,
                rec.street,
                rec.country,
                rec.postal_code,
                rec.region,
                rec.fluxer_id,
                rec.discord_id,
                rec.irc_id,
            ] {
                if !r.is_empty() {
                    let end = r.offset.saturating_add(u32::from(r.len));
                    heap_bump = heap_bump.max(end);
                }
            }
            if rec.key_len > 0 {
                let end = rec.key_offset.saturating_add(u32::from(rec.key_len));
                key_bump = key_bump.max(end);
            }
        }
        (heap_bump, key_bump)
    }

    /// Boot path: verify CRC on occupied slots, rebuild index, verify integrity, open gate.
    pub fn init_on_boot(&mut self) -> Result<(), ContactStoreError> {
        let mut records = [ContactRecord::default(); 54];
        for (i, rec) in records.iter_mut().enumerate() {
            let mut buf = [0u8; CONTACT_RECORD_BYTES];
            self.storage
                .read(Self::record_offset(i as u8), &mut buf)
                .map_err(|_| ContactStoreError::StorageRead)?;
            if buf[0..4] == CONTACT_RECORD_MAGIC.to_le_bytes() {
                *rec = ContactRecord::from_bytes_verified(&buf)?;
            }
        }
        let (hb, kb) = Self::scan_bumps(&records);
        self.string_heap.set_bump(hb);
        self.key_region.set_bump(kb);
        self.index.rebuild_from_records(&records);
        self.verify_integrity()?;
        Ok(())
    }

    /// Recompute integrity digest and compare to the backup register mirror; opens gate on success.
    pub fn verify_integrity(&mut self) -> Result<(), ContactStoreError> {
        if self.read_provision_marker()? == 0 {
            self.integrity_gate = false;
            return Err(ContactStoreError::NotProvisioned);
        }
        self.load_integrity_register()?;
        let digest = self.compute_integrity_digest()?;
        if !bool::from(digest.ct_eq(&self.integrity_register)) {
            self.integrity_gate = false;
            return Err(ContactStoreError::IntegrityMismatch);
        }
        self.integrity_gate = true;
        Ok(())
    }

    /// Update backup-register mirror after a committed mutation.
    pub fn update_integrity(&mut self) -> Result<(), ContactStoreError> {
        self.integrity_register = self.compute_integrity_digest()?;
        self.persist_integrity_register()
    }

    /// Append a timing-log entry (monotonic sequence from [`MonotonicCounter`]).
    pub fn timing_log_append(
        &mut self,
        slot: SlotIndex,
        last_fetched: u32,
    ) -> Result<(), ContactStoreError> {
        self.gate()?;
        let mut records = [ContactRecord::default(); 54];
        for (i, rec) in records.iter_mut().enumerate().take(CONTACT_SLOT_COUNT) {
            *rec = self.read_record(i as u8)?;
        }
        TimingLog::append(
            &mut self.timing_log,
            &mut self.storage,
            &mut self.counter,
            slot,
            last_fetched,
            &mut records,
        )
    }

    /// Read timing-log entry by index.
    pub fn timing_log_read_entry(&self, index: usize) -> Result<TimingLogEntry, ContactStoreError> {
        self.gate()?;
        TimingLog::read_entry(&self.storage, index)
    }

    /// Monotonic counter value (integration tests / host diagnostics).
    #[cfg(any(test, feature = "test-hal"))]
    pub fn counter_value(&self) -> Result<u32, ContactStoreError> {
        self.counter
            .read()
            .map_err(|_| ContactStoreError::CounterError)
    }

    /// Read bytes from backing RRAM (integration tests).
    #[cfg(any(test, feature = "test-hal"))]
    pub fn read_storage(&self, offset: u64, out: &mut [u8]) -> Result<(), ContactStoreError> {
        self.storage
            .read(offset, out)
            .map_err(|_| ContactStoreError::StorageRead)
    }

    /// Write bytes to backing RRAM (integration tests).
    #[cfg(any(test, feature = "test-hal"))]
    pub fn write_storage(&mut self, offset: u64, data: &[u8]) -> Result<(), ContactStoreError> {
        self.storage
            .write(offset, data)
            .map_err(|_| ContactStoreError::StorageWrite)
    }

    fn compute_integrity_digest(&self) -> Result<[u8; 32], ContactStoreError> {
        let mut key = [0u8; 32];
        derive_subkey_sha512(
            &self.master_key,
            &[],
            KeyPurpose::ContactStoreIntegrity,
            &mut key,
        )
        .map_err(|_| ContactStoreError::Crypto)?;
        let mut hasher = blake3::Hasher::new_keyed(&key);
        for slot in 0..CONTACT_SLOT_COUNT {
            let mut buf = [0u8; CONTACT_RECORD_BYTES];
            self.storage
                .read(Self::record_offset(slot as u8), &mut buf)
                .map_err(|_| ContactStoreError::StorageRead)?;
            if buf[0..4] == CONTACT_RECORD_MAGIC.to_le_bytes() {
                if !crate::crc::record_crc_ok(buf.as_slice()) {
                    return Err(ContactStoreError::CorruptRecord);
                }
                hasher.update(&buf);
            }
        }
        let mut log_buf = [0u8; 256];
        let mut pos = TIMING_LOG_OFFSET;
        let end = TIMING_LOG_OFFSET + u64::from(TIMING_LOG_BYTES);
        while pos < end {
            let chunk = log_buf.len() as u64;
            if pos + chunk > end {
                break;
            }
            self.storage
                .read(pos, &mut log_buf)
                .map_err(|_| ContactStoreError::StorageRead)?;
            hasher.update(&log_buf);
            pos += chunk;
        }
        Ok(*hasher.finalize().as_bytes())
    }

    fn alloc_string(&mut self, bytes: &[u8]) -> Result<StringRef, ContactStoreError> {
        if bytes.len() > usize::from(MAX_STRING_FIELD_BYTES) {
            return Err(ContactStoreError::StringTooLong);
        }
        StringHeap::alloc(&mut self.string_heap, &mut self.storage, bytes)
    }

    fn find_empty_recipient_slot(&self) -> Result<u8, ContactStoreError> {
        for slot in RECIPIENT_SLOT_START..(RECIPIENT_SLOT_START as usize + RECIPIENT_SLOT_COUNT) as u8
        {
            let mut buf = [0u8; 4];
            self.storage
                .read(Self::record_offset(slot), &mut buf)
                .map_err(|_| ContactStoreError::StorageRead)?;
            if u32::from_le_bytes(buf) != CONTACT_RECORD_MAGIC {
                return Ok(slot);
            }
        }
        Err(ContactStoreError::RecipientSlotsFull)
    }

    fn find_empty_own_slot(&self) -> Result<u8, ContactStoreError> {
        for slot in 0..4u8 {
            let mut buf = [0u8; 4];
            self.storage
                .read(Self::record_offset(slot), &mut buf)
                .map_err(|_| ContactStoreError::StorageRead)?;
            if u32::from_le_bytes(buf) != CONTACT_RECORD_MAGIC {
                return Ok(slot);
            }
        }
        Err(ContactStoreError::RecipientSlotsFull)
    }

    /// Insert a new contact.
    pub fn insert(&mut self, input: NewContact<'_>) -> Result<SlotIndex, ContactStoreError> {
        self.gate()?;
        let slot = if input.own_identity {
            self.find_empty_own_slot()?
        } else {
            self.find_empty_recipient_slot()?
        };
        let (key_off, key_len) =
            KeyMaterialRegion::alloc(&mut self.key_region, &mut self.storage, input.public_key)?;
        let mut flags = ContactFlags::ACTIVE;
        if input.own_identity {
            flags |= ContactFlags::SELF_KEY;
        }
        let (pin_verifier, pin_nonce, pin_tag) = if input.pin_protected {
            let pv = input.pin_verifier.ok_or(ContactStoreError::PinFailed)?;
            (
                pv,
                input.pin_nonce.unwrap_or([0u8; 12]),
                input.pin_tag.unwrap_or([0u8; 16]),
            )
        } else {
            ([0u8; 32], [0u8; 12], [0u8; 16])
        };
        let email = self.alloc_string(input.email)?;
        let display_name = if let Some(name) = input.display_name {
            self.alloc_string(name)?
        } else {
            StringRef::default()
        };
        let mut rec = ContactRecord {
            magic: CONTACT_RECORD_MAGIC,
            flags: flags.bits(),
            key_algo: input.key_algo.to_wire(),
            pin_protected: if input.pin_protected { 1 } else { 0 },
            reserved0: 0,
            fingerprint: input.fingerprint,
            callsign: input.callsign,
            dmr_id: input.dmr_id,
            key_offset: key_off,
            key_len,
            reserved1: 0,
            pin_nonce,
            pin_tag,
            last_fetched: 0,
            source_map: field_source_set(0, field::EMAIL, FieldSource::HostVerified),
            pin_verifier,
            email,
            display_name,
            badge_number: StringRef::default(),
            organisation: StringRef::default(),
            department: StringRef::default(),
            role: StringRef::default(),
            note: StringRef::default(),
            radio_affiliation: StringRef::default(),
            street: StringRef::default(),
            country: StringRef::default(),
            postal_code: StringRef::default(),
            region: StringRef::default(),
            fluxer_id: StringRef::default(),
            discord_id: StringRef::default(),
            irc_id: StringRef::default(),
            reserved2: [0u8; 26],
            crc32c: 0,
        };
        rec.recompute_crc();
        self.write_record(slot, &rec)?;
        self.index
            .insert(&rec.fingerprint, slot, rec.contact_flags())?;
        self.update_integrity()?;
        Ok(SlotIndex(slot))
    }

    fn lookup_slot_by_fp(&self, fp: &[u8; 32]) -> Result<u8, ContactStoreError> {
        self.gate()?;
        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&fp[..16]);
        let slot = self
            .index
            .lookup_prefix(&prefix)
            .ok_or(ContactStoreError::SlotNotFound)?;
        let rec = self.read_record(slot)?;
        if !bool::from(rec.fingerprint.ct_eq(fp)) {
            return Err(ContactStoreError::SlotNotFound);
        }
        Ok(slot)
    }

    /// Lookup by full fingerprint.
    pub fn lookup_by_fingerprint(&self, fp: &[u8; 32]) -> Result<ContactRecord, ContactStoreError> {
        let slot = self.lookup_slot_by_fp(fp)?;
        self.read_record(slot)
    }

    /// Lookup by callsign (fixed 12-byte field).
    pub fn lookup_by_callsign(&self, callsign: &[u8; 12]) -> Result<ContactRecord, ContactStoreError> {
        self.gate()?;
        for slot in 0..CONTACT_SLOT_COUNT as u8 {
            let rec = self.read_record(slot)?;
            if rec.is_active() && bool::from(rec.callsign.ct_eq(callsign)) {
                return Ok(rec);
            }
        }
        Err(ContactStoreError::SlotNotFound)
    }

    /// Lookup by DMR subscriber id.
    pub fn lookup_by_dmr_id(&self, dmr_id: u32) -> Result<ContactRecord, ContactStoreError> {
        self.gate()?;
        if dmr_id == 0 {
            return Err(ContactStoreError::SlotNotFound);
        }
        for slot in 0..CONTACT_SLOT_COUNT as u8 {
            let rec = self.read_record(slot)?;
            if rec.is_active() && rec.dmr_id == dmr_id {
                return Ok(rec);
            }
        }
        Err(ContactStoreError::SlotNotFound)
    }

    /// Lookup by e-mail (scans string heap).
    pub fn lookup_by_email(&self, email: &str) -> Result<ContactRecord, ContactStoreError> {
        self.gate()?;
        let target = email.as_bytes();
        let mut buf = [0u8; 256];
        for slot in 0..CONTACT_SLOT_COUNT as u8 {
            let rec = self.read_record(slot)?;
            if !rec.is_active() || rec.email.is_empty() {
                continue;
            }
            let len = usize::from(rec.email.len);
            if len > buf.len() {
                continue;
            }
            StringHeap::read(
                &self.string_heap,
                &self.storage,
                rec.email,
                &mut buf[..len],
            )?;
            if &buf[..len] == target {
                return Ok(rec);
            }
        }
        Err(ContactStoreError::SlotNotFound)
    }

    /// Update mutable fields.
    pub fn update(
        &mut self,
        slot: SlotIndex,
        update: ContactUpdate<'_>,
    ) -> Result<(), ContactStoreError> {
        self.gate()?;
        let mut rec = self.read_record(slot.0)?;
        if !rec.is_active() {
            return Err(ContactStoreError::InvalidSlot);
        }
        if let Some(cs) = update.callsign {
            rec.callsign = cs;
        }
        if let Some(id) = update.dmr_id {
            rec.dmr_id = id;
        }
        if let Some(email) = update.email {
            rec.email = self.alloc_string(email)?;
        }
        if let Some(name) = update.display_name {
            rec.display_name = self.alloc_string(name)?;
        }
        if let Some(ts) = update.last_fetched {
            rec.last_fetched = ts;
        }
        if let Some(stale) = update.stale {
            let mut f = rec.contact_flags();
            if stale {
                f |= ContactFlags::STALE;
            } else {
                f -= ContactFlags::STALE;
            }
            rec.set_contact_flags(f);
            self.index.update_flags(slot.0, f);
        }
        rec.recompute_crc();
        self.write_record(slot.0, &rec)?;
        self.update_integrity()?;
        Ok(())
    }

    /// Mark slot inactive (zero magic).
    pub fn delete(&mut self, slot: SlotIndex) -> Result<(), ContactStoreError> {
        self.gate()?;
        let rec = ContactRecord::default();
        self.write_record(slot.0, &rec)?;
        self.index.remove(slot.0);
        self.update_integrity()?;
        Ok(())
    }

    /// List occupied slots with fingerprints.
    pub fn list(&self) -> Result<ContactListIter, ContactStoreError> {
        self.gate()?;
        let mut items = [(0u8, [0u8; 32]); 54];
        let mut len = 0u8;
        for e in self.index.iter() {
            let rec = self.read_record(e.slot)?;
            items[usize::from(len)] = (e.slot, rec.fingerprint);
            len += 1;
        }
        Ok(ContactListIter {
            items,
            len,
            pos: 0,
        })
    }

    /// Read public key for a non-PIN-protected record.
    pub fn read_public_key(&self, slot: SlotIndex) -> Result<PublicKeyBlob, ContactStoreError> {
        self.gate()?;
        let rec = self.read_record(slot.0)?;
        if rec.pin_protected != 0 {
            return Err(ContactStoreError::PinRequired);
        }
        let mut buf = [0u8; MAX_PUBLIC_KEY_BYTES];
        KeyMaterialRegion::read(
            &self.key_region,
            &self.storage,
            rec.key_offset,
            rec.key_len,
            &mut buf,
        )?;
        PublicKeyBlob::from_slice(&buf[..usize::from(rec.key_len)])
    }

    /// Unlock PIN-protected key material (`pin-policy` counter before compare).
    pub fn unlock_pin_protected<Z: ZeroisationTrigger>(
        &mut self,
        slot: SlotIndex,
        pin: &PinBuffer,
        machine: &mut PinPolicyMachine<Z>,
    ) -> Result<PublicKeyBlob, ContactStoreError> {
        self.gate()?;
        let rec = self.read_record(slot.0)?;
        if rec.pin_protected == 0 {
            return self.read_public_key(slot);
        }
        let verifier = rec.pin_verifier;
        let pin_bytes = pin.as_slice();
        let outcome = machine
            .submit_attempt(&mut self.counter, || pin_compare(pin_bytes, &verifier))
            .map_err(|_| ContactStoreError::CounterError)?;
        match outcome {
            PinOutcome::Success => {}
            PinOutcome::Failed { .. } | PinOutcome::Breach => {
                return Err(ContactStoreError::PinFailed);
            }
        }
        let mut wrap_key = [0u8; 32];
        derive_subkey_sha512(
            &self.master_key,
            &[],
            KeyPurpose::ContactKeyWrap,
            &mut wrap_key,
        )
        .map_err(|_| ContactStoreError::Crypto)?;
        let mut ct = [0u8; MAX_PUBLIC_KEY_BYTES];
        let len = usize::from(rec.key_len);
        KeyMaterialRegion::read(
            &self.key_region,
            &self.storage,
            rec.key_offset,
            rec.key_len,
            &mut ct,
        )?;
        let mut plain = [0u8; MAX_PUBLIC_KEY_BYTES];
        let plen = aes_gcm_decrypt(
            &wrap_key,
            &rec.pin_nonce,
            &rec.pin_tag,
            &ct[..len],
            &mut plain,
        )?;
        PublicKeyBlob::from_slice(&plain[..plen])
    }

}

fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    tag: &[u8; 16],
    ciphertext: &[u8],
    plain_out: &mut [u8],
) -> Result<usize, ContactStoreError> {
    if ciphertext.len() + 16 > plain_out.len() {
        return Err(ContactStoreError::Crypto);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut combined = [0u8; MAX_PUBLIC_KEY_BYTES + 16];
    combined[..ciphertext.len()].copy_from_slice(ciphertext);
    combined[ciphertext.len()..ciphertext.len() + 16].copy_from_slice(tag);
    let nonce_ga = Nonce::from_slice(nonce);
    let plain = cipher
        .decrypt(nonce_ga, &combined[..ciphertext.len() + 16])
        .map_err(|_| ContactStoreError::Crypto)?;
    if plain.len() > plain_out.len() {
        return Err(ContactStoreError::Crypto);
    }
    plain_out[..plain.len()].copy_from_slice(&plain);
    Ok(plain.len())
}

impl<S, C> Drop for ContactStore<S, C> {
    fn drop(&mut self) {
        self.master_key.zeroize();
        self.integrity_register.zeroize();
    }
}
