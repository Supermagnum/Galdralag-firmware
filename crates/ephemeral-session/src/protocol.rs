//! Session state machine for authenticated ephemeral ECDH.
//!
//! ECDH and ECDSA use the same Brainpool implementations as the Wycheproof-backed vault tests
//! (`BrainpoolScalar::diffie_hellman`, `BrainpoolSigningKey::sign_handshake_sha256_prehash`, etc.).
//! No additional Wycheproof runners are required for this protocol layer.

#![deny(unsafe_code)]

use crate::curve_select::SessionCurve;
use crate::error::EphemeralSessionError;
use crate::handshake::{
    InitMessage, ResponseMessage, INIT_PROTOCOL_VERSION, RESP_PROTOCOL_VERSION,
};
use crate::keys::{EphemeralKeyPair, SessionKeys};
use crate::trust::LongTermCert;
use galdr_core::hal::{HardwareTrng, VaultStorage};
use subtle::ConstantTimeEq;
use galdr_vault::rsa_vault::KeySlot;
use galdr_vault::session_long_term_signing::{
    vault_load_session_long_term_signing_key, SessionLongTermSigningKey,
};

/// The role of this node in the session handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Session initiator (sends [`InitMessage`] first).
    Initiator,
    /// Session responder (replies with [`ResponseMessage`]).
    Responder,
}

/// Initiator side: step 1 of 2.
pub struct InitiatorSession {
    state: InitiatorState,
}

// Ephemeral handshake state is intentionally stored inline (no heap); the large
// `Initialised` variant is acceptable for embedded stack usage.
#[allow(clippy::large_enum_variant)]
enum InitiatorState {
    New,
    Initialised {
        curve: SessionCurve,
        ephemeral_keypair: EphemeralKeyPair,
        init_message: InitMessage,
    },
    Completed,
}

impl InitiatorSession {
    /// Create a new initiator session.
    pub fn new() -> Self {
        Self {
            state: InitiatorState::New,
        }
    }

    /// Step 1: generate ephemeral key pair and produce [`InitMessage`].
    pub fn init<T: HardwareTrng, S: VaultStorage>(
        &mut self,
        curve: SessionCurve,
        long_term_slot: &KeySlot,
        trng: &mut T,
        storage: &mut S,
    ) -> Result<InitMessage, EphemeralSessionError> {
        match &self.state {
            InitiatorState::Completed => return Err(EphemeralSessionError::SessionAlreadyCompleted),
            InitiatorState::Initialised { .. } => {
                return Err(EphemeralSessionError::SessionAlreadyInitialised);
            }
            InitiatorState::New => {}
        }
        let lt = vault_load_session_long_term_signing_key(storage, long_term_slot, curve.wire_id())?;
        let epk = EphemeralKeyPair::generate(curve, trng)?;
        let preimage = init_sign_preimage(INIT_PROTOCOL_VERSION, curve, epk.public_key_bytes());
        let sig = sign_with_long_term(&lt, preimage.as_slice(), trng)?;
        let vk_sec1 = verifying_sec1(&lt)?;
        let raw_fp = LongTermCert::fingerprint_of(vk_sec1.as_slice());
        let mut raw_arr = [0u8; 32];
        raw_arr.copy_from_slice(raw_fp.as_slice());
        let fp_hex = InitMessage::encode_fingerprint_hex(&raw_arr);
        let mut long_term_fingerprint = heapless::Vec::new();
        long_term_fingerprint
            .extend_from_slice(fp_hex.as_slice())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let mut signature = heapless::Vec::new();
        signature
            .extend_from_slice(sig.as_slice())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let mut ephemeral_public_key = heapless::Vec::new();
        ephemeral_public_key
            .extend_from_slice(epk.public_key_bytes())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let init_message = InitMessage {
            version: INIT_PROTOCOL_VERSION,
            curve,
            ephemeral_public_key,
            long_term_fingerprint,
            signature,
        };
        let out = init_message.clone();
        self.state = InitiatorState::Initialised {
            curve,
            ephemeral_keypair: epk,
            init_message,
        };
        Ok(out)
    }

    /// Step 2: verify the [`ResponseMessage`] and derive [`SessionKeys`].
    pub fn complete(
        &mut self,
        response: &ResponseMessage,
        peer_long_term_cert: &LongTermCert,
    ) -> Result<SessionKeys, EphemeralSessionError> {
        let st = core::mem::replace(&mut self.state, InitiatorState::New);
        match st {
            InitiatorState::Initialised {
                curve,
                ephemeral_keypair,
                init_message,
            } => self.complete_inner(
                curve,
                ephemeral_keypair,
                init_message,
                response,
                peer_long_term_cert,
            ),
            InitiatorState::Completed => {
                self.state = InitiatorState::Completed;
                Err(EphemeralSessionError::SessionAlreadyCompleted)
            }
            InitiatorState::New => Err(EphemeralSessionError::MalformedHandshake),
        }
    }

    fn complete_inner(
        &mut self,
        curve: SessionCurve,
        epk: EphemeralKeyPair,
        init_message: InitMessage,
        response: &ResponseMessage,
        peer_long_term_cert: &LongTermCert,
    ) -> Result<SessionKeys, EphemeralSessionError> {
        if response.version != RESP_PROTOCOL_VERSION {
            self.state = InitiatorState::Initialised {
                curve,
                ephemeral_keypair: epk,
                init_message,
            };
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        if response.curve != curve {
            self.state = InitiatorState::Initialised {
                curve,
                ephemeral_keypair: epk,
                init_message,
            };
            return Err(EphemeralSessionError::CurveMismatch);
        }
        let my_epk = init_message.ephemeral_public_key.as_slice();
        if my_epk.len() != response.initiator_ephemeral_public_key.len()
            || bool::from(!my_epk.ct_eq(response.initiator_ephemeral_public_key.as_slice()))
        {
            self.state = InitiatorState::Initialised {
                curve,
                ephemeral_keypair: epk,
                init_message,
            };
            return Err(EphemeralSessionError::InvalidPeerSignature);
        }
        let wire_fp = match InitMessage::decode_fingerprint_hex(response.long_term_fingerprint.as_slice()) {
            Ok(x) => x,
            Err(e) => {
                self.state = InitiatorState::Initialised {
                    curve,
                    ephemeral_keypair: epk,
                    init_message,
                };
                return Err(e);
            }
        };
        if bool::from(!peer_long_term_cert.fingerprint.as_slice().ct_eq(&wire_fp)) {
            self.state = InitiatorState::Initialised {
                curve,
                ephemeral_keypair: epk,
                init_message,
            };
            return Err(EphemeralSessionError::FingerprintMismatch);
        }
        let resp_pre = response_sign_preimage(
            RESP_PROTOCOL_VERSION,
            curve,
            response.ephemeral_public_key.as_slice(),
            response.initiator_ephemeral_public_key.as_slice(),
        );
        if let Err(e) = verify_with_cert(
            peer_long_term_cert,
            resp_pre.as_slice(),
            response.signature.as_slice(),
        ) {
            self.state = InitiatorState::Initialised {
                curve,
                ephemeral_keypair: epk,
                init_message,
            };
            return Err(e);
        }
        let shared = epk
            .ecdh(response.ephemeral_public_key.as_slice())
            .inspect_err(|_| {
                self.state = InitiatorState::New;
            })?;
        let keys = shared
            .derive_session_keys(
                init_message.ephemeral_public_key.as_slice(),
                response.ephemeral_public_key.as_slice(),
            )
            .inspect_err(|_| {
                self.state = InitiatorState::New;
            })?;
        self.state = InitiatorState::Completed;
        Ok(keys)
    }
}

impl Default for InitiatorSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Responder side (single-shot).
pub struct ResponderSession;

impl ResponderSession {
    /// Verify [`InitMessage`], run ECDH, derive keys, and produce [`ResponseMessage`].
    pub fn respond<T: HardwareTrng, S: VaultStorage>(
        init_message: &InitMessage,
        long_term_slot: &KeySlot,
        peer_long_term_cert: &LongTermCert,
        trng: &mut T,
        storage: &mut S,
    ) -> Result<(ResponseMessage, SessionKeys), EphemeralSessionError> {
        if init_message.version != INIT_PROTOCOL_VERSION {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let curve = init_message.curve;
        let wire_fp = InitMessage::decode_fingerprint_hex(init_message.long_term_fingerprint.as_slice())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        if bool::from(!peer_long_term_cert.fingerprint.as_slice().ct_eq(&wire_fp)) {
            return Err(EphemeralSessionError::FingerprintMismatch);
        }
        let init_pre = init_sign_preimage(
            init_message.version,
            curve,
            init_message.ephemeral_public_key.as_slice(),
        );
        verify_with_cert(
            peer_long_term_cert,
            init_pre.as_slice(),
            init_message.signature.as_slice(),
        )?;
        let lt = vault_load_session_long_term_signing_key(storage, long_term_slot, curve.wire_id())?;
        let epk = EphemeralKeyPair::generate(curve, trng)?;
        let resp_pre = response_sign_preimage(
            RESP_PROTOCOL_VERSION,
            curve,
            epk.public_key_bytes(),
            init_message.ephemeral_public_key.as_slice(),
        );
        let sig = sign_with_long_term(&lt, resp_pre.as_slice(), trng)?;
        let vk_sec1 = verifying_sec1(&lt)?;
        let raw_fp = LongTermCert::fingerprint_of(vk_sec1.as_slice());
        let mut raw_arr = [0u8; 32];
        raw_arr.copy_from_slice(raw_fp.as_slice());
        let fp_hex = InitMessage::encode_fingerprint_hex(&raw_arr);
        let mut long_term_fingerprint = heapless::Vec::new();
        long_term_fingerprint
            .extend_from_slice(fp_hex.as_slice())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let mut signature = heapless::Vec::new();
        signature
            .extend_from_slice(sig.as_slice())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let mut ephemeral_public_key = heapless::Vec::new();
        ephemeral_public_key
            .extend_from_slice(epk.public_key_bytes())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let mut initiator_ephemeral_public_key = heapless::Vec::new();
        initiator_ephemeral_public_key
            .extend_from_slice(init_message.ephemeral_public_key.as_slice())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let response = ResponseMessage {
            version: RESP_PROTOCOL_VERSION,
            curve,
            ephemeral_public_key,
            long_term_fingerprint,
            initiator_ephemeral_public_key,
            signature,
        };
        let shared = epk.ecdh(init_message.ephemeral_public_key.as_slice())?;
        let keys = shared.derive_session_keys(
            init_message.ephemeral_public_key.as_slice(),
            response.ephemeral_public_key.as_slice(),
        )?;
        Ok((response, keys))
    }
}

fn init_sign_preimage(version: u8, curve: SessionCurve, epk: &[u8]) -> heapless::Vec<u8, 200> {
    let mut p = heapless::Vec::new();
    p.push(version).expect("v");
    p.push(curve.wire_id()).expect("c");
    p.extend_from_slice(epk).expect("epk");
    p
}

fn response_sign_preimage(
    version: u8,
    curve: SessionCurve,
    responder_epk: &[u8],
    initiator_epk: &[u8],
) -> heapless::Vec<u8, 400> {
    let mut p = heapless::Vec::new();
    p.push(version).expect("v");
    p.push(curve.wire_id()).expect("c");
    p.extend_from_slice(responder_epk).expect("r");
    p.extend_from_slice(initiator_epk).expect("i");
    p
}

fn sign_with_long_term<T: HardwareTrng>(
    key: &SessionLongTermSigningKey,
    preimage: &[u8],
    trng: &mut T,
) -> Result<heapless::Vec<u8, 200>, EphemeralSessionError> {
    match key {
        SessionLongTermSigningKey::P256(sk) => {
            let s = sk
                .sign_handshake_sha256_prehash(preimage, trng)
                .map_err(|_| EphemeralSessionError::InvalidPeerSignature)?;
            let mut v = heapless::Vec::new();
            v.extend_from_slice(s.der_bytes())
                .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
            Ok(v)
        }
        SessionLongTermSigningKey::P384(sk) => {
            let s = sk
                .sign_handshake_sha256_prehash(preimage, trng)
                .map_err(|_| EphemeralSessionError::InvalidPeerSignature)?;
            let mut v = heapless::Vec::new();
            v.extend_from_slice(s.der_bytes())
                .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
            Ok(v)
        }
        SessionLongTermSigningKey::P512(sk) => {
            let s = sk
                .sign_handshake_sha256_prehash(preimage, trng)
                .map_err(|_| EphemeralSessionError::InvalidPeerSignature)?;
            let mut v = heapless::Vec::new();
            v.extend_from_slice(s.der_bytes())
                .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
            Ok(v)
        }
    }
}

fn verifying_sec1(key: &SessionLongTermSigningKey) -> Result<heapless::Vec<u8, 129>, EphemeralSessionError> {
    match key {
        SessionLongTermSigningKey::P256(sk) => {
            let vk = sk.verifying_key();
            let b = vk.to_sec1_uncompressed();
            let mut v = heapless::Vec::new();
            v.extend_from_slice(&b).map_err(|_| EphemeralSessionError::MalformedHandshake)?;
            Ok(v)
        }
        SessionLongTermSigningKey::P384(sk) => {
            let vk = sk.verifying_key();
            let b = vk.to_sec1_uncompressed();
            let mut v = heapless::Vec::new();
            v.extend_from_slice(&b).map_err(|_| EphemeralSessionError::MalformedHandshake)?;
            Ok(v)
        }
        SessionLongTermSigningKey::P512(sk) => {
            let vk = sk.verifying_key();
            let b = vk.to_sec1_uncompressed();
            let mut v = heapless::Vec::new();
            v.extend_from_slice(&b).map_err(|_| EphemeralSessionError::MalformedHandshake)?;
            Ok(v)
        }
    }
}

fn verify_with_cert(
    cert: &LongTermCert,
    preimage: &[u8],
    der_sig: &[u8],
) -> Result<(), EphemeralSessionError> {
    match cert.curve {
        SessionCurve::BrainpoolP256r1 => {
            use galdr_vault::ecdsa_brainpool::{BrainpoolSignature, BrainpoolVerifyingKey};
            let vk = BrainpoolVerifyingKey::from_sec1(cert.verifying_key.as_slice())
                .map_err(|_| EphemeralSessionError::InvalidPeerPublicKey)?;
            let sig = BrainpoolSignature::from_der_bytes(der_sig)
                .map_err(|_| EphemeralSessionError::InvalidPeerSignature)?;
            vk.verify_handshake_sha256_prehash(preimage, &sig)
                .map_err(|_| EphemeralSessionError::InvalidPeerSignature)
        }
        SessionCurve::BrainpoolP384r1 => {
            use galdr_vault::brainpool384::{BrainpoolP384Signature, BrainpoolP384VerifyingKey};
            let vk = BrainpoolP384VerifyingKey::from_sec1(cert.verifying_key.as_slice())
                .map_err(|_| EphemeralSessionError::InvalidPeerPublicKey)?;
            let sig = BrainpoolP384Signature::from_der_bytes(der_sig)
                .map_err(|_| EphemeralSessionError::InvalidPeerSignature)?;
            vk.verify_handshake_sha256_prehash(preimage, &sig)
                .map_err(|_| EphemeralSessionError::InvalidPeerSignature)
        }
        SessionCurve::BrainpoolP512r1 => {
            use galdr_vault::brainpool512::{BrainpoolP512Signature, BrainpoolP512VerifyingKey};
            let vk = BrainpoolP512VerifyingKey::from_sec1(cert.verifying_key.as_slice())
                .map_err(|_| EphemeralSessionError::InvalidPeerPublicKey)?;
            let sig = BrainpoolP512Signature::from_der_bytes(der_sig)
                .map_err(|_| EphemeralSessionError::InvalidPeerSignature)?;
            vk.verify_handshake_sha256_prehash(preimage, &sig)
                .map_err(|_| EphemeralSessionError::InvalidPeerSignature)
        }
    }
}
