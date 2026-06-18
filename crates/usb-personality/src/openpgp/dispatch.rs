//! OpenPGP INS dispatcher (APDU to response).

#![deny(unsafe_code)]

use galdr_vault::KeyPurpose;
use heapless::Vec;

use crate::ccid::{
    atr_openpgp_profile, rdr_to_pc_data_block, rdr_to_pc_parameters, rdr_to_pc_slot_status,
    CcidStatus, PcToRdr, CCID_WIRE_BUF_SIZE,
};

use super::aid::aid_matches_openpgp;
use super::apdu::{CommandApdu, ResponseApdu};
use super::backend::{OpenPgpBackend, OpenPgpBackendError, OpenPgpKeySlot};
use super::commands::decipher::parse_ecdh_peer_public_key;
use super::dos::{curve_oids, extended_capabilities_default, AlgorithmAttributes};
use super::error::StatusWord;
use super::state::CardState;

const INS_SELECT: u8 = 0xA4;
const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_REFERENCE: u8 = 0x24;
const INS_PSO: u8 = 0x2A;
const INS_INTERNAL_AUTH: u8 = 0x88;
const INS_GET_RESPONSE: u8 = 0xC0;
const INS_GET_DATA: u8 = 0xCA;
const INS_PUT_DATA: u8 = 0xDA;
const INS_PUT_DATA_ODD: u8 = 0xDB;
const INS_GENERATE_KEY: u8 = 0x47;
const INS_RESET_RETRY_COUNTER: u8 = 0x2C;
const INS_GET_CHALLENGE: u8 = 0x84;
const INS_MANAGE_SECURITY_ENVIRONMENT: u8 = 0x22;

fn curve_oid_matches(oid: &heapless::Vec<u8, 16>, expected: &[u8]) -> bool {
    oid.as_slice() == expected
}

fn parse_mse_key_ref(data: &[u8]) -> Option<u8> {
    if data.len() >= 3 && data[0] == 0x83 && data[1] == 0x01 {
        Some(data[2])
    } else {
        None
    }
}

fn map_err(e: OpenPgpBackendError) -> ResponseApdu {
    ResponseApdu::error(e.to_status_word())
}

fn trim_openpgp_pin_padding(buf: &[u8]) -> &[u8] {
    let mut end = buf.len();
    while end > 0 && buf[end - 1] == 0xFF {
        end -= 1;
    }
    &buf[..end]
}

fn handle_change_reference<B: OpenPgpBackend>(
    cmd: &CommandApdu,
    _state: &mut CardState,
    backend: &mut B,
) -> ResponseApdu {
    if cmd.p1 != 0x00 {
        return ResponseApdu::error(StatusWord::WrongParametersP1P2);
    }
    let pw3 = match cmd.p2 {
        0x81 => false,
        0x83 => true,
        _ => return ResponseApdu::error(StatusWord::WrongParametersP1P2),
    };
    let pw = backend.pw_status_bytes();
    let pin_len = if pw3 { pw[1] as usize } else { pw[0] as usize };
    if pin_len == 0 || pin_len > 127 {
        return ResponseApdu::error(StatusWord::IncorrectParameters);
    }
    let Some(total) = pin_len.checked_mul(2) else {
        return ResponseApdu::error(StatusWord::IncorrectParameters);
    };
    if cmd.data.len() != total {
        return ResponseApdu::error(StatusWord::WrongLength);
    }
    let (old_raw, new_raw) = cmd.data.split_at(pin_len);
    let old_pin = trim_openpgp_pin_padding(old_raw);
    let new_pin = trim_openpgp_pin_padding(new_raw);
    if new_pin.is_empty() {
        return ResponseApdu::error(StatusWord::IncorrectParameters);
    }
    match backend.change_pin(pw3, old_pin, new_pin) {
        Ok(()) => {
            backend.log_event(0x24_0000 | u32::from(cmd.p2));
            ResponseApdu::ok_empty()
        }
        Err(e) => map_err(e),
    }
}

fn le_limit(cmd: &CommandApdu) -> usize {
    cmd.le
        .map(|l| {
            if l == 0 {
                256usize
            } else {
                usize::from(l.min(512))
            }
        })
        .unwrap_or(256)
}

fn encode_tlv(tag: u16, value: &[u8], out: &mut Vec<u8, 512>) -> Result<(), ()> {
    if tag <= 0xFF {
        out.push(tag as u8).map_err(|_| ())?;
    } else {
        out.push((tag >> 8) as u8).map_err(|_| ())?;
        out.push(tag as u8).map_err(|_| ())?;
    }
    let len = value.len();
    if len <= 0x7F {
        out.push(len as u8).map_err(|_| ())?;
    } else if len <= 0xFF {
        out.push(0x81).map_err(|_| ())?;
        out.push(len as u8).map_err(|_| ())?;
    } else {
        out.push(0x82).map_err(|_| ())?;
        out.push((len >> 8) as u8).map_err(|_| ())?;
        out.push(len as u8).map_err(|_| ())?;
    }
    for b in value {
        out.push(*b).map_err(|_| ())?;
    }
    Ok(())
}

/// Handle one command APDU; updates `state` and uses `backend` for vault operations.
pub fn handle_apdu<B: OpenPgpBackend>(
    cmd: &CommandApdu,
    state: &mut CardState,
    backend: &mut B,
) -> ResponseApdu {
    if backend.is_termination_state() {
        if cmd.ins == INS_VERIFY {
            return ResponseApdu::error(StatusWord::AuthMethodBlocked);
        }
        return ResponseApdu::error(StatusWord::TerminationState);
    }

    match cmd.ins {
        INS_GET_RESPONSE => handle_get_response(cmd, state, backend),
        INS_SELECT => handle_select(cmd, state, backend),
        INS_VERIFY => handle_verify(cmd, state, backend),
        INS_GET_DATA => handle_get_data(cmd, state, backend),
        INS_PUT_DATA | INS_PUT_DATA_ODD => handle_put_data(cmd, state, backend),
        INS_PSO => handle_pso(cmd, state, backend),
        INS_INTERNAL_AUTH => handle_internal_auth(cmd, state, backend),
        INS_GENERATE_KEY => handle_generate(cmd, state, backend),
        INS_CHANGE_REFERENCE => handle_change_reference(cmd, state, backend),
        INS_RESET_RETRY_COUNTER => handle_reset_retry_counter(cmd, state, backend),
        INS_GET_CHALLENGE => handle_get_challenge(cmd, backend),
        INS_MANAGE_SECURITY_ENVIRONMENT => handle_manage_security_environment(cmd, state),
        _ => ResponseApdu::error(StatusWord::InstructionNotSupported),
    }
}

fn handle_get_challenge<B: OpenPgpBackend>(cmd: &CommandApdu, backend: &mut B) -> ResponseApdu {
    if cmd.p1 != 0x00 || cmd.p2 != 0x00 {
        return ResponseApdu::error(StatusWord::WrongParametersP1P2);
    }
    let len = match cmd.le {
        None => return ResponseApdu::error(StatusWord::WrongLength),
        Some(l) => {
            let n = usize::from(l);
            if n == 0 || n > 64 {
                return ResponseApdu::error(StatusWord::WrongLength);
            }
            n
        }
    };
    match backend.get_challenge(len) {
        Ok(bytes) => {
            let mut out = Vec::new();
            for b in bytes.iter() {
                if out.push(*b).is_err() {
                    return ResponseApdu::error(StatusWord::ExecutionError);
                }
            }
            ResponseApdu::ok(out)
        }
        Err(_) => ResponseApdu::error(StatusWord::ExecutionError),
    }
}

fn handle_manage_security_environment(cmd: &CommandApdu, state: &mut CardState) -> ResponseApdu {
    if cmd.p1 != 0x41 {
        return ResponseApdu::error(StatusWord::ConditionsNotSatisfied);
    }
    let key_ref = match parse_mse_key_ref(cmd.data.as_slice()) {
        Some(k) => k,
        None => return ResponseApdu::error(StatusWord::IncorrectParameters),
    };
    match cmd.p2 {
        0xB6 => state.mse_sig_key_ref = Some(key_ref),
        0xB8 => state.mse_dec_key_ref = Some(key_ref),
        0xA4 => state.mse_aut_key_ref = Some(key_ref),
        _ => return ResponseApdu::error(StatusWord::WrongParametersP1P2),
    }
    ResponseApdu::ok_empty()
}

fn handle_reset_retry_counter<B: OpenPgpBackend>(
    cmd: &CommandApdu,
    state: &mut CardState,
    backend: &mut B,
) -> ResponseApdu {
    if cmd.p1 == 0x02 {
        return ResponseApdu::error(StatusWord::ReferenceDataNotFound);
    }
    if cmd.p1 != 0x00 || cmd.p2 != 0x81 {
        return ResponseApdu::error(StatusWord::WrongParametersP1P2);
    }
    if !state.is_pw3_verified() {
        return ResponseApdu::error(StatusWord::SecurityStatusNotSatisfied);
    }
    let pw = backend.pw_status_bytes();
    let min_len = pw[0] as usize;
    if min_len == 0 || min_len > 127 {
        return ResponseApdu::error(StatusWord::IncorrectParameters);
    }
    let new_pin = trim_openpgp_pin_padding(cmd.data.as_slice());
    if new_pin.len() < min_len {
        return ResponseApdu::error(StatusWord::WrongLength);
    }
    match backend.set_pw1_verifier_admin_only(new_pin) {
        Ok(()) => {}
        Err(e) => return map_err(e),
    }
    match backend.reset_pw1_retry_counter() {
        Ok(()) => {
            backend.log_event(0x2C_0081);
            ResponseApdu::ok_empty()
        }
        Err(e) => map_err(e),
    }
}

fn handle_select<B: OpenPgpBackend>(
    cmd: &CommandApdu,
    _state: &mut CardState,
    backend: &mut B,
) -> ResponseApdu {
    if cmd.p1 != 0x04 || (cmd.p2 != 0x00 && cmd.p2 != 0x04) {
        return ResponseApdu::error(StatusWord::WrongParametersP1P2);
    }
    if !aid_matches_openpgp(cmd.data.as_slice()) {
        return ResponseApdu::error(StatusWord::FileNotFound);
    }
    backend.log_event(0xA4_0001);
    ResponseApdu::ok_empty()
}

fn handle_verify<B: OpenPgpBackend>(
    cmd: &CommandApdu,
    state: &mut CardState,
    backend: &mut B,
) -> ResponseApdu {
    let pin = cmd.data.as_slice();
    let r = match cmd.p2 {
        0x81 => backend.verify_pw1_sign(pin),
        0x82 => backend.verify_pw1_other(pin),
        0x83 => backend.verify_pw3(pin),
        _ => return ResponseApdu::error(StatusWord::WrongParametersP1P2),
    };
    match r {
        Ok(()) => {
            match cmd.p2 {
                0x81 => state.set_pw1_sign(true),
                0x82 => state.set_pw1_other(true),
                0x83 => state.set_pw3(true),
                _ => {}
            }
            backend.log_event(0x20_0000 | u32::from(cmd.p2));
            ResponseApdu::ok_empty()
        }
        Err(OpenPgpBackendError::Status(s)) => ResponseApdu::error(s),
        Err(e) => map_err(e),
    }
}

fn do_tag<B: OpenPgpBackend>(
    tag: u16,
    backend: &mut B,
) -> Result<Vec<u8, 512>, OpenPgpBackendError> {
    match tag {
        0x004F => {
            let aid = backend.aid_bytes();
            let mut out = Vec::new();
            for b in aid {
                out.push(*b)
                    .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
            }
            Ok(out)
        }
        0x6E => {
            let mut buf = Vec::new();
            let aid = backend.aid_bytes();
            encode_tlv(0x4F, aid, &mut buf)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
            let ext = extended_capabilities_default();
            encode_tlv(0xC0, &ext, &mut buf)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
            let atr = atr_openpgp_profile();
            encode_tlv(0x5F52, atr, &mut buf)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
            Ok(buf)
        }
        0x65 => {
            let mut buf = Vec::new();
            let name = backend.get_do(0x5B)?;
            let lang = backend.get_do(0x5F2D)?;
            let sex = backend.get_do(0x5F35)?;
            encode_tlv(0x5B, name.as_slice(), &mut buf)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
            encode_tlv(0x5F2D, lang.as_slice(), &mut buf)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
            encode_tlv(0x5F35, sex.as_slice(), &mut buf)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
            let mut outer = Vec::new();
            encode_tlv(0x65, buf.as_slice(), &mut outer)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
            Ok(outer)
        }
        0x7A => {
            let mut buf = Vec::new();
            let ctr = backend.get_do(0x93)?;
            encode_tlv(0x93, ctr.as_slice(), &mut buf)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
            let mut outer = Vec::new();
            encode_tlv(0x7A, buf.as_slice(), &mut outer)
                .map_err(|_| OpenPgpBackendError::Status(StatusWord::ExecutionError))?;
            Ok(outer)
        }
        _ => backend.get_do(tag),
    }
}

fn handle_get_data<B: OpenPgpBackend>(
    cmd: &CommandApdu,
    state: &mut CardState,
    backend: &mut B,
) -> ResponseApdu {
    let tag = u16::from(cmd.p1) << 8 | u16::from(cmd.p2);
    let data = match do_tag(tag, backend) {
        Ok(d) => d,
        Err(e) => return map_err(e),
    };
    chunk_response(cmd, state, data)
}

fn put_requires_pw3(tag: u16) -> bool {
    matches!(
        tag,
        0x5B | 0x5F2D | 0x5F35 | 0x5E | 0x5F50 | 0xC1 | 0xC2 | 0xC3 | 0xC4 | 0x7F21
    ) || (0xC7..=0xCE).contains(&tag)
        || (0xD1..=0xD3).contains(&tag)
        || tag == 0xF4
}

fn put_allowed(state: &CardState, tag: u16) -> bool {
    if (0x0101..=0x0104).contains(&tag) {
        return state.is_pw1_other_verified();
    }
    if put_requires_pw3(tag) {
        return state.is_pw3_verified();
    }
    state.is_pw3_verified()
}

fn handle_put_data<B: OpenPgpBackend>(
    cmd: &CommandApdu,
    state: &mut CardState,
    backend: &mut B,
) -> ResponseApdu {
    let tag = u16::from(cmd.p1) << 8 | u16::from(cmd.p2);
    if !put_allowed(state, tag) {
        return ResponseApdu::error(StatusWord::SecurityStatusNotSatisfied);
    }
    match backend.put_do(tag, cmd.data.as_slice()) {
        Ok(()) => {
            backend.log_event(0xDA_0000 | u32::from(tag));
            ResponseApdu::ok_empty()
        }
        Err(e) => map_err(e),
    }
}

fn slot_from_p2(p2: u8) -> Option<OpenPgpKeySlot> {
    match p2 {
        0xB6 => Some(OpenPgpKeySlot::Sig),
        0xB8 => Some(OpenPgpKeySlot::Dec),
        0xA4 => Some(OpenPgpKeySlot::Aut),
        _ => None,
    }
}

fn handle_pso<B: OpenPgpBackend>(
    cmd: &CommandApdu,
    state: &mut CardState,
    backend: &mut B,
) -> ResponseApdu {
    if cmd.p1 == 0x9E && cmd.p2 == 0x9A {
        if !state.is_pw1_sign_verified() {
            return ResponseApdu::error(StatusWord::SecurityStatusNotSatisfied);
        }
        let hash = cmd.data.as_slice();
        let attrs = backend.algorithm_attributes(OpenPgpKeySlot::Sig);
        let sig = match attrs {
            AlgorithmAttributes::Ecdsa { .. } => match backend.pso_sign_hash(hash) {
                Ok(s) => s,
                Err(e) => return map_err(e),
            },
            AlgorithmAttributes::EdDsa { curve_oid }
                if curve_oid_matches(&curve_oid, curve_oids::ED25519) =>
            {
                match backend.ed25519_sign(KeyPurpose::OpenPgpSig, hash) {
                    Ok(s) => {
                        let mut v = Vec::new();
                        for b in s.iter() {
                            if v.push(*b).is_err() {
                                return ResponseApdu::error(StatusWord::ExecutionError);
                            }
                        }
                        v
                    }
                    Err(e) => return map_err(e),
                }
            }
            _ => return ResponseApdu::error(StatusWord::ConditionsNotSatisfied),
        };
        if let Err(e) = backend.increment_signature_counter() {
            return map_err(e);
        }
        state.consume_pw1_sign();
        backend.log_event(0x2A_9E9A);
        return chunk_response(cmd, state, sig);
    }
    if cmd.p1 == 0x80 && cmd.p2 == 0x86 {
        if !state.is_pw1_other_verified() {
            return ResponseApdu::error(StatusWord::SecurityStatusNotSatisfied);
        }
        let data = cmd.data.as_slice();
        if let Some(peer) = parse_ecdh_peer_public_key(data) {
            backend.log_event(0x2A_8086);
            let dec_attrs = backend.algorithm_attributes(OpenPgpKeySlot::Dec);
            let mut out = Vec::new();
            match dec_attrs {
                AlgorithmAttributes::Ecdh { curve_oid }
                    if curve_oid_matches(&curve_oid, curve_oids::CURVE25519) =>
                {
                    let shared = match backend.x25519_ecdh(KeyPurpose::OpenPgpDec, peer) {
                        Ok(s) => s,
                        Err(e) => return map_err(e),
                    };
                    for b in shared.iter() {
                        if out.push(*b).is_err() {
                            return ResponseApdu::error(StatusWord::ExecutionError);
                        }
                    }
                }
                AlgorithmAttributes::Ecdh { .. } => {
                    let shared = match backend.ecdh_dec(KeyPurpose::OpenPgpDec, peer) {
                        Ok(s) => s,
                        Err(e) => return map_err(e),
                    };
                    for b in shared.iter() {
                        if out.push(*b).is_err() {
                            return ResponseApdu::error(StatusWord::ExecutionError);
                        }
                    }
                }
                _ => return ResponseApdu::error(StatusWord::ConditionsNotSatisfied),
            }
            return chunk_response(cmd, state, out);
        }
        backend.log_event(0x2A_8086);
        let out = match backend.pso_decipher(data) {
            Ok(s) => s,
            Err(e) => return map_err(e),
        };
        return chunk_response(cmd, state, out);
    }
    ResponseApdu::error(StatusWord::WrongParametersP1P2)
}

fn handle_internal_auth<B: OpenPgpBackend>(
    cmd: &CommandApdu,
    state: &mut CardState,
    backend: &mut B,
) -> ResponseApdu {
    if !state.is_pw1_other_verified() {
        return ResponseApdu::error(StatusWord::SecurityStatusNotSatisfied);
    }
    let out = match backend.internal_authenticate(cmd.data.as_slice()) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    backend.log_event(0x88_0000);
    chunk_response(cmd, state, out)
}

fn handle_generate<B: OpenPgpBackend>(
    cmd: &CommandApdu,
    state: &mut CardState,
    backend: &mut B,
) -> ResponseApdu {
    let slot = match slot_from_p2(cmd.p2) {
        Some(s) => s,
        None => return ResponseApdu::error(StatusWord::WrongParametersP1P2),
    };
    if cmd.p1 == 0x80 && !state.is_pw3_verified() {
        return ResponseApdu::error(StatusWord::SecurityStatusNotSatisfied);
    }
    let out = match backend.generate_or_read_key(cmd.p1, slot) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    if cmd.p1 == 0x80 {
        backend.log_event(0x47_0000 | u32::from(cmd.p2));
    }
    chunk_response(cmd, state, out)
}

fn handle_get_response<B: OpenPgpBackend>(
    cmd: &CommandApdu,
    state: &mut CardState,
    _backend: &mut B,
) -> ResponseApdu {
    let lim = le_limit(cmd);
    let remaining = state
        .response_buffer
        .len()
        .saturating_sub(state.response_offset);
    if remaining == 0 {
        return ResponseApdu::error(StatusWord::WrongParametersP1P2);
    }
    let take = remaining.min(lim);
    let mut chunk = Vec::new();
    let start = state.response_offset;
    for b in state.response_buffer.iter().skip(start).take(take) {
        if chunk.push(*b).is_err() {
            return ResponseApdu::error(StatusWord::ExecutionError);
        }
    }
    state.response_offset += take;
    let left = remaining.saturating_sub(take);
    if left > 0 {
        let n = u8::try_from(left.min(255)).unwrap_or(255);
        ResponseApdu {
            data: chunk,
            sw1: StatusWord::MoreDataAvailable(n).sw1(),
            sw2: StatusWord::MoreDataAvailable(n).sw2(),
        }
    } else {
        state.response_buffer.clear();
        state.response_offset = 0;
        ResponseApdu::ok(chunk)
    }
}

fn chunk_response(cmd: &CommandApdu, state: &mut CardState, data: Vec<u8, 512>) -> ResponseApdu {
    let lim = le_limit(cmd);
    if data.len() <= lim {
        return ResponseApdu::ok(data);
    }
    state.response_buffer.clear();
    state.response_offset = 0;
    for b in data.iter() {
        let _ = state.response_buffer.push(*b);
    }
    let take = state.response_buffer.len().min(lim);
    let mut chunk = Vec::new();
    for b in state.response_buffer.iter().take(take) {
        let _ = chunk.push(*b);
    }
    state.response_offset = take;
    let remaining = state.response_buffer.len().saturating_sub(take);
    let n = if remaining > 255 {
        0xFF
    } else {
        u8::try_from(remaining).unwrap_or(0xFF)
    };
    ResponseApdu {
        data: chunk,
        sw1: StatusWord::MoreDataAvailable(n).sw1(),
        sw2: StatusWord::MoreDataAvailable(n).sw2(),
    }
}

/// Minimal interface between the USB CCID layer and the OpenPGP dispatcher.
pub trait OpenPgpDispatch {
    /// Handle one parsed PC_to_RDR message; returns a full RDR_to_PC frame for Bulk IN.
    fn handle_ccid(&mut self, msg: PcToRdr) -> Vec<u8, CCID_WIRE_BUF_SIZE>;

    /// USB bus reset: clear card session state.
    fn on_usb_reset(&mut self);
}

/// [`OpenPgpBackend`] + [`CardState`] wired for CCID (ATR, APDU, slot status).
pub struct OpenPgpCcidDispatcher<B: OpenPgpBackend> {
    state: CardState,
    backend: B,
}

impl<B: OpenPgpBackend> OpenPgpCcidDispatcher<B> {
    pub fn new(backend: B) -> Self {
        Self {
            state: CardState::new(),
            backend,
        }
    }

    pub fn into_inner(self) -> B {
        self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn state_mut(&mut self) -> &mut CardState {
        &mut self.state
    }
}

impl<B: OpenPgpBackend> OpenPgpDispatch for OpenPgpCcidDispatcher<B> {
    fn handle_ccid(&mut self, msg: PcToRdr) -> Vec<u8, CCID_WIRE_BUF_SIZE> {
        match msg {
            PcToRdr::IccPowerOn { slot, seq, .. } => rdr_to_pc_parameters(slot, seq),
            PcToRdr::IccPowerOff { slot, seq } => {
                self.state.reset();
                rdr_to_pc_slot_status(slot, seq, CcidStatus::ok_active())
            }
            PcToRdr::GetSlotStatus { slot, seq } => {
                rdr_to_pc_slot_status(slot, seq, CcidStatus::ok_active())
            }
            PcToRdr::XfrBlock { slot, seq, apdu } => match CommandApdu::parse(apdu.as_slice()) {
                Ok(cmd) => {
                    let resp = handle_apdu(&cmd, &mut self.state, &mut self.backend);
                    let bytes = resp.to_bytes();
                    rdr_to_pc_data_block(slot, seq, CcidStatus::ok_active(), bytes.as_slice())
                }
                Err(_) => rdr_to_pc_slot_status(slot, seq, CcidStatus::cmd_not_supported()),
            },
            PcToRdr::Abort { slot, seq } => {
                self.state.reset();
                rdr_to_pc_slot_status(slot, seq, CcidStatus::ok_active())
            }
        }
    }

    fn on_usb_reset(&mut self) {
        self.state.reset();
        self.backend.on_lock_disconnect();
    }
}
