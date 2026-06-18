//! Ephemeral key pairs and derived session keys.

use cess::derive_k_outer;
use crate::curve_select::SessionCurve;
use crate::error::EphemeralSessionError;
use galdr_core::hal::HardwareTrng;
use heapless::Vec;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use vault::brainpool::BrainpoolPublicKey;
use vault::brainpool384::BrainpoolP384PublicKey;
use vault::brainpool512::BrainpoolP512PublicKey;
use vault::brainpool::BrainpoolScalar;
use vault::brainpool384::BrainpoolP384Scalar;
use vault::brainpool512::BrainpoolP512Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Maximum length of a Brainpool P-512r1 ECDH shared secret (x-coordinate).
const MAX_SHARED: usize = 64;

/// An ephemeral key pair generated on the token for a single session.
/// The private key is zeroised immediately after ECDH completes.
/// No `Clone`, no `Copy`.
pub struct EphemeralKeyPair {
    curve: SessionCurve,
    /// The ephemeral public key in uncompressed SEC1 form.
    public_key: Vec<u8, 129>,
    /// The ephemeral private scalar (only first `private_len` bytes are defined).
    private_key: Zeroizing<[u8; 64]>,
    private_len: u8,
}

impl EphemeralKeyPair {
    /// Generate a fresh ephemeral key pair using the hardware TRNG.
    pub fn generate<T: HardwareTrng>(
        curve: SessionCurve,
        trng: &mut T,
    ) -> Result<Self, EphemeralSessionError> {
        match curve {
            SessionCurve::BrainpoolP256r1 => {
                let sk = BrainpoolScalar::generate(trng).map_err(|_| EphemeralSessionError::KeyGeneration)?;
                let pk = sk.public_key().map_err(|_| EphemeralSessionError::KeyGeneration)?;
                let sec1 = pk.to_sec1_uncompressed();
                let mut public_key = Vec::new();
                public_key
                    .extend_from_slice(&sec1)
                    .map_err(|_| EphemeralSessionError::KeyGeneration)?;
                let raw = sk.to_secret_bytes_for_test();
                let mut private_key = Zeroizing::new([0u8; 64]);
                private_key[..32].copy_from_slice(&raw);
                Ok(EphemeralKeyPair {
                    curve,
                    public_key,
                    private_key,
                    private_len: 32,
                })
            }
            SessionCurve::BrainpoolP384r1 => {
                let sk = BrainpoolP384Scalar::generate(trng).map_err(|_| EphemeralSessionError::KeyGeneration)?;
                let pk = sk.public_key().map_err(|_| EphemeralSessionError::KeyGeneration)?;
                let sec1 = pk.to_sec1_uncompressed();
                let mut public_key = Vec::new();
                public_key
                    .extend_from_slice(&sec1)
                    .map_err(|_| EphemeralSessionError::KeyGeneration)?;
                let raw = sk.to_secret_bytes_for_test();
                let mut private_key = Zeroizing::new([0u8; 64]);
                private_key[..48].copy_from_slice(&raw);
                Ok(EphemeralKeyPair {
                    curve,
                    public_key,
                    private_key,
                    private_len: 48,
                })
            }
            SessionCurve::BrainpoolP512r1 => {
                let sk = BrainpoolP512Scalar::generate(trng).map_err(|_| EphemeralSessionError::KeyGeneration)?;
                let pk = sk.public_key().map_err(|_| EphemeralSessionError::KeyGeneration)?;
                let sec1 = pk.to_sec1_uncompressed();
                let mut public_key = Vec::new();
                public_key
                    .extend_from_slice(&sec1)
                    .map_err(|_| EphemeralSessionError::KeyGeneration)?;
                let raw = sk.to_secret_bytes_for_test();
                let private_key = Zeroizing::new(raw);
                Ok(EphemeralKeyPair {
                    curve,
                    public_key,
                    private_key,
                    private_len: 64,
                })
            }
        }
    }

    /// The ephemeral public key in uncompressed SEC1 form.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.public_key.as_slice()
    }

    /// Perform ECDH with the peer's ephemeral public key.
    /// Consumes `self` — the private key is zeroised after this call
    /// regardless of whether ECDH succeeds or fails.
    pub fn ecdh(self, peer_public_key: &[u8]) -> Result<EphemeralSharedSecret, EphemeralSessionError> {
        let EphemeralKeyPair {
            curve,
            public_key: _,
            private_key,
            private_len,
        } = self;
        let sk = &private_key[..private_len as usize];
        let shared = match curve {
            SessionCurve::BrainpoolP256r1 => {
                let s = BrainpoolScalar::from_secret_key_bytes_for_test(sk)
                    .map_err(|_| EphemeralSessionError::EcdhFailed)?;
                let peer = BrainpoolPublicKey::from_sec1(peer_public_key)
                    .map_err(|_| EphemeralSessionError::InvalidPeerPublicKey)?;
                let x = s.diffie_hellman(&peer).map_err(|_| EphemeralSessionError::EcdhFailed)?;
                pack_shared(x.as_bytes())?
            }
            SessionCurve::BrainpoolP384r1 => {
                let s = BrainpoolP384Scalar::from_secret_key_bytes_for_test(sk)
                    .map_err(|_| EphemeralSessionError::EcdhFailed)?;
                let peer = BrainpoolP384PublicKey::from_sec1(peer_public_key)
                    .map_err(|_| EphemeralSessionError::InvalidPeerPublicKey)?;
                let x = s.diffie_hellman(&peer).map_err(|_| EphemeralSessionError::EcdhFailed)?;
                pack_shared(x.as_bytes())?
            }
            SessionCurve::BrainpoolP512r1 => {
                let s = BrainpoolP512Scalar::from_secret_key_bytes_for_test(sk)
                    .map_err(|_| EphemeralSessionError::EcdhFailed)?;
                let peer = BrainpoolP512PublicKey::from_sec1(peer_public_key)
                    .map_err(|_| EphemeralSessionError::InvalidPeerPublicKey)?;
                let x = s.diffie_hellman(&peer).map_err(|_| EphemeralSessionError::EcdhFailed)?;
                pack_shared(x.as_bytes())?
            }
        };
        Ok(EphemeralSharedSecret(shared))
    }

    /// Test-only: read private scalar bytes (padded to 64 bytes).
    #[cfg(test)]
    pub(crate) fn private_key_bytes_for_test(&self) -> [u8; 64] {
        *self.private_key
    }
}

fn pack_shared(bytes: &[u8]) -> Result<SharedSecretInner, EphemeralSessionError> {
    if bytes.len() > MAX_SHARED {
        return Err(EphemeralSessionError::EcdhFailed);
    }
    let mut a = Zeroizing::new([0u8; MAX_SHARED]);
    a[..bytes.len()].copy_from_slice(bytes);
    Ok(SharedSecretInner {
        bytes: a,
        len: bytes.len() as u8,
    })
}

struct SharedSecretInner {
    bytes: Zeroizing<[u8; MAX_SHARED]>,
    len: u8,
}

/// Raw ECDH output. Zeroised on drop. Never leaves this crate
/// without going through HKDF first.
/// Opaque ECDH shared secret (zeroised after HKDF in [`EphemeralSharedSecret::derive_session_keys`]).
pub struct EphemeralSharedSecret(SharedSecretInner);

impl EphemeralSharedSecret {
    /// Derive **CESS** Mode A **`K_outer`** from the raw ECDH shared secret (HKDF-BLAKE3,
    /// `info = cess-outer-envelope-v1`). Call **before** [`derive_session_keys`](Self::derive_session_keys),
    /// which consumes the shared secret.
    ///
    /// For normative **Mode A** outer key agreement, the handshake **must** use **BrainpoolP384r1**
    /// ephemeral ECDH only (CESS §6.1.1); the IKM length is then the P-384 **x** coordinate encoding
    /// used by this stack (see `pack_shared` / vault ECDH).
    pub fn cess_k_outer_mode_a(&self) -> [u8; 32] {
        let ikm = &self.0.bytes[..self.0.len as usize];
        derive_k_outer(ikm)
    }

    /// Derive all session keys via HKDF-SHA256.
    /// Salt is `min(epk_initiator, epk_responder) || max(epk_initiator, epk_responder)`.
    /// Consumes `self` — the shared secret is zeroised after derivation.
    pub(crate) fn derive_session_keys(
        self,
        epk_initiator: &[u8],
        epk_responder: &[u8],
    ) -> Result<SessionKeys, EphemeralSessionError> {
        let inner = self.0;
        let salt = ordered_epk_salt(epk_initiator, epk_responder)?;
        let ikm = &inner.bytes[..inner.len as usize];
        let prk_arr = hkdf_extract_sha256(salt.as_slice(), ikm);
        let profile_prk_material = Zeroizing::new(prk_arr);
        let hk = Hkdf::<Sha256>::from_prk(profile_prk_material.as_slice())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let mut payload_key_i2r = Zeroizing::new([0u8; 32]);
        let mut payload_key_r2i = Zeroizing::new([0u8; 32]);
        let mut gdss_mask_key = Zeroizing::new([0u8; 32]);
        let mut gdss_sync_key = Zeroizing::new([0u8; 32]);
        let mut gdss_timing_key = Zeroizing::new([0u8; 32]);
        let mut mac_key = Zeroizing::new([0u8; 32]);
        hk.expand(crate::domain::PAYLOAD_KEY_I2R, payload_key_i2r.as_mut())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        hk.expand(crate::domain::PAYLOAD_KEY_R2I, payload_key_r2i.as_mut())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        hk.expand(crate::domain::GDSS_MASK_KEY, gdss_mask_key.as_mut())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        hk.expand(crate::domain::GDSS_SYNC_KEY, gdss_sync_key.as_mut())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        hk.expand(crate::domain::GDSS_TIMING_KEY, gdss_timing_key.as_mut())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        hk.expand(crate::domain::MAC_KEY, mac_key.as_mut())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let mut classical_ecdh_ikm_storage = Zeroizing::new([0u8; MAX_SHARED]);
        classical_ecdh_ikm_storage[..inner.len as usize].copy_from_slice(ikm);
        Ok(SessionKeys {
            classical_ecdh_ikm_storage,
            classical_ecdh_ikm_len: inner.len,
            profile_prk_material,
            payload_key_i2r,
            payload_key_r2i,
            gdss_mask_key,
            gdss_sync_key,
            gdss_timing_key,
            mac_key,
        })
    }

    /// Test-only: shared bytes before HKDF.
    #[cfg(test)]
    pub(crate) fn as_bytes_for_test(&self) -> &[u8] {
        &self.0.bytes[..self.0.len as usize]
    }
}

/// HKDF-Extract (RFC 5869) for SHA-256: PRK = HMAC-SHA256(salt, IKM), `salt` as HMAC key.
/// If `salt` is empty, uses a string of HashLen (32) zero octets as the HMAC key.
fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    if salt.is_empty() {
        let key = [0u8; 32];
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).expect("hmac key");
        mac.update(ikm);
        return mac.finalize().into_bytes().into();
    }
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("hmac key");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

fn ordered_epk_salt(
    epk_initiator: &[u8],
    epk_responder: &[u8],
) -> Result<Vec<u8, 258>, EphemeralSessionError> {
    let mut salt = Vec::new();
    if epk_initiator <= epk_responder {
        salt.extend_from_slice(epk_initiator)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        salt.extend_from_slice(epk_responder)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
    } else {
        salt.extend_from_slice(epk_responder)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        salt.extend_from_slice(epk_initiator)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
    }
    Ok(salt)
}

/// All derived session keys. Each key is independent. All zeroise on drop.
/// No `Clone`, no `Copy`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Raw classical ECDH shared secret (packed `x` coordinate); same IKM as
    /// [`EphemeralSharedSecret::cess_k_outer_mode_a`]. Retained for CESS §8.3 inner cascade
    /// HKDF-BLAKE3 (`cipher_profile::cascade_encrypt` / `cascade_decrypt`); not the same bytes as
    /// [`Self::profile_prk`].
    classical_ecdh_ikm_storage: Zeroizing<[u8; MAX_SHARED]>,
    classical_ecdh_ikm_len: u8,
    /// HKDF-Extract output (SHA-256) from the ephemeral shared secret with EPK-ordered salt;
    /// used for cipher-profile **custom** profiles (no CESS `suite_id` mapping) only.
    profile_prk_material: Zeroizing<[u8; 32]>,
    /// ChaCha20-Poly1305 payload key initiator to responder.
    pub payload_key_i2r: Zeroizing<[u8; 32]>,
    /// ChaCha20-Poly1305 payload key responder to initiator.
    pub payload_key_r2i: Zeroizing<[u8; 32]>,
    /// GDSS masking keystream key.
    pub gdss_mask_key: Zeroizing<[u8; 32]>,
    /// GDSS sync PN key.
    pub gdss_sync_key: Zeroizing<[u8; 32]>,
    /// GDSS timing schedule key.
    pub gdss_timing_key: Zeroizing<[u8; 32]>,
    /// Optional HMAC key.
    pub mac_key: Zeroizing<[u8; 32]>,
}

impl SessionKeys {
    /// Classical ECDH output octets for CESS-mapped cipher profiles: pass this slice to
    /// `cipher_profile::cascade_encrypt` / `cascade_decrypt` as `ikm` (CESS §8.3).
    pub fn cess_inner_cascade_ikm(&self) -> &[u8] {
        &self.classical_ecdh_ikm_storage[..self.classical_ecdh_ikm_len as usize]
    }

    /// Raw HKDF pseudorandom key (HKDF-Extract output) for cipher-profile cascade key derivation
    /// on **custom** profiles (no built-in CESS `suite_id`). For built-in registry profiles use
    /// [`Self::cess_inner_cascade_ikm`] instead.
    pub fn profile_prk(&self) -> &[u8; 32] {
        &self.profile_prk_material
    }

    /// Extract the four key material slices in the order expected by GR-K-GDSS.
    ///
    /// Returns `(payload_encrypt, gdss_mask, gdss_sync, gdss_timing)`.
    ///
    /// GR-K-GDSS uses a single payload key; this returns `payload_key_i2r` as the
    /// payload encryption key. The caller chooses direction keys by role.
    pub fn as_gdss_keys(
        &self,
    ) -> (
        &[u8; 32],
        &[u8; 32],
        &[u8; 32],
        &[u8; 32],
    ) {
        (
            &self.payload_key_i2r,
            &self.gdss_mask_key,
            &self.gdss_sync_key,
            &self.gdss_timing_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use galdr_core::fake_hal::FakeTrng;
    use subtle::ConstantTimeEq;

    #[test]
    fn ephemeral_keypair_generate_lengths() {
        for curve in [
            SessionCurve::BrainpoolP256r1,
            SessionCurve::BrainpoolP384r1,
            SessionCurve::BrainpoolP512r1,
        ] {
            let mut trng = FakeTrng::from_seed(0x51);
            let kp = EphemeralKeyPair::generate(curve, &mut trng).expect("gen");
            assert_eq!(kp.public_key_bytes().len(), curve.public_key_len());
        }
    }

    #[test]
    fn ecdh_commutativity() {
        let mut t1 = FakeTrng::from_seed(1);
        let mut t2 = FakeTrng::from_seed(2);
        let curve = SessionCurve::BrainpoolP256r1;
        let a = EphemeralKeyPair::generate(curve, &mut t1).expect("a");
        let b = EphemeralKeyPair::generate(curve, &mut t2).expect("b");
        let pa = a.public_key_bytes().to_vec();
        let pb = b.public_key_bytes().to_vec();
        let sa = a.ecdh(pb.as_slice()).expect("sa");
        let sb = b.ecdh(pa.as_slice()).expect("sb");
        assert!(bool::from(
            sa.as_bytes_for_test().ct_eq(sb.as_bytes_for_test())
        ));
    }

    #[test]
    fn ecdh_zeroises_private_key() {
        let mut trng = FakeTrng::from_seed(0x33);
        let curve = SessionCurve::BrainpoolP256r1;
        let pair = EphemeralKeyPair::generate(curve, &mut trng).expect("gen");
        let before = pair.private_key_bytes_for_test();
        assert!(before.iter().any(|x| *x != 0));
        let mut trng2 = FakeTrng::from_seed(2);
        let peer = EphemeralKeyPair::generate(curve, &mut trng2).expect("peer");
        let _ = pair.ecdh(peer.public_key_bytes()).expect("ecdh");
        let _ = before;
    }

    #[test]
    fn shared_secret_zeroised_after_derive() {
        let mut t1 = FakeTrng::from_seed(3);
        let mut t2 = FakeTrng::from_seed(4);
        let curve = SessionCurve::BrainpoolP256r1;
        let a = EphemeralKeyPair::generate(curve, &mut t1).expect("a");
        let b = EphemeralKeyPair::generate(curve, &mut t2).expect("b");
        let pa = a.public_key_bytes().to_vec();
        let pb = b.public_key_bytes().to_vec();
        let s = a.ecdh(&pb).expect("ecdh");
        let _keys = s
            .derive_session_keys(pa.as_slice(), pb.as_slice())
            .expect("derive");
    }

    #[test]
    fn session_keys_all_distinct() {
        let mut t1 = FakeTrng::from_seed(5);
        let mut t2 = FakeTrng::from_seed(6);
        let curve = SessionCurve::BrainpoolP256r1;
        let a = EphemeralKeyPair::generate(curve, &mut t1).expect("a");
        let b = EphemeralKeyPair::generate(curve, &mut t2).expect("b");
        let pa = a.public_key_bytes().to_vec();
        let pb = b.public_key_bytes().to_vec();
        let s = a.ecdh(&pb).expect("ecdh");
        let keys = s
            .derive_session_keys(pa.as_slice(), pb.as_slice())
            .expect("derive");
        let v = [
            keys.payload_key_i2r.as_slice(),
            keys.payload_key_r2i.as_slice(),
            keys.gdss_mask_key.as_slice(),
            keys.gdss_sync_key.as_slice(),
            keys.gdss_timing_key.as_slice(),
            keys.mac_key.as_slice(),
        ];
        for i in 0..v.len() {
            for j in i + 1..v.len() {
                assert_ne!(v[i], v[j]);
            }
        }
    }

    #[test]
    fn cess_k_outer_mode_a_deterministic_before_derive() {
        let mut t1 = FakeTrng::from_seed(0x41);
        let mut t2 = FakeTrng::from_seed(0x42);
        let curve = SessionCurve::BrainpoolP384r1;
        let a = EphemeralKeyPair::generate(curve, &mut t1).expect("a");
        let b = EphemeralKeyPair::generate(curve, &mut t2).expect("b");
        let pa = a.public_key_bytes().to_vec();
        let pb = b.public_key_bytes().to_vec();
        let s = a.ecdh(pb.as_slice()).expect("ecdh");
        let k1 = s.cess_k_outer_mode_a();
        let k2 = s.cess_k_outer_mode_a();
        assert_eq!(k1, k2);
        let _keys = s
            .derive_session_keys(pa.as_slice(), pb.as_slice())
            .expect("derive");
    }

    #[test]
    fn cess_inner_cascade_ikm_retains_raw_ecdh() {
        let mut t1 = FakeTrng::from_seed(0x61);
        let mut t2 = FakeTrng::from_seed(0x62);
        let curve = SessionCurve::BrainpoolP384r1;
        let a = EphemeralKeyPair::generate(curve, &mut t1).expect("a");
        let b = EphemeralKeyPair::generate(curve, &mut t2).expect("b");
        let pa = a.public_key_bytes().to_vec();
        let pb = b.public_key_bytes().to_vec();
        let s = a.ecdh(pb.as_slice()).expect("ecdh");
        let raw = s.as_bytes_for_test().to_vec();
        let keys = s
            .derive_session_keys(pa.as_slice(), pb.as_slice())
            .expect("derive");
        assert_eq!(keys.cess_inner_cascade_ikm(), raw.as_slice());
    }

    #[test]
    fn session_keys_deterministic() {
        let mut t1 = FakeTrng::from_seed(7);
        let mut t2 = FakeTrng::from_seed(8);
        let curve = SessionCurve::BrainpoolP256r1;
        let a = EphemeralKeyPair::generate(curve, &mut t1).expect("a");
        let b = EphemeralKeyPair::generate(curve, &mut t2).expect("b");
        let pa = a.public_key_bytes().to_vec();
        let pb = b.public_key_bytes().to_vec();
        let s1 = a.ecdh(pb.as_slice()).expect("ecdh");
        let k1 = s1
            .derive_session_keys(pa.as_slice(), pb.as_slice())
            .expect("derive");
        let mut t3 = FakeTrng::from_seed(7);
        let mut t4 = FakeTrng::from_seed(8);
        let a2 = EphemeralKeyPair::generate(curve, &mut t3).expect("a2");
        let b2 = EphemeralKeyPair::generate(curve, &mut t4).expect("b2");
        let pa2 = a2.public_key_bytes().to_vec();
        let pb2 = b2.public_key_bytes().to_vec();
        let s2 = a2.ecdh(pb2.as_slice()).expect("ecdh2");
        let k2 = s2
            .derive_session_keys(pa2.as_slice(), pb2.as_slice())
            .expect("derive2");
        assert_eq!(k1.payload_key_i2r.as_ref(), k2.payload_key_i2r.as_ref());
    }

    #[test]
    fn session_keys_salt_order_independent() {
        let mut t1 = FakeTrng::from_seed(9);
        let mut t2 = FakeTrng::from_seed(10);
        let curve = SessionCurve::BrainpoolP256r1;
        let a = EphemeralKeyPair::generate(curve, &mut t1).expect("a");
        let b = EphemeralKeyPair::generate(curve, &mut t2).expect("b");
        let pa = a.public_key_bytes().to_vec();
        let pb = b.public_key_bytes().to_vec();
        let s = a.ecdh(pb.as_slice()).expect("ecdh");
        let k1 = s
            .derive_session_keys(pa.as_slice(), pb.as_slice())
            .expect("derive");
        let mut t3 = FakeTrng::from_seed(9);
        let mut t4 = FakeTrng::from_seed(10);
        let a2 = EphemeralKeyPair::generate(curve, &mut t3).expect("a2");
        let b2 = EphemeralKeyPair::generate(curve, &mut t4).expect("b2");
        let pa2 = a2.public_key_bytes().to_vec();
        let pb2 = b2.public_key_bytes().to_vec();
        let s2 = a2.ecdh(pb2.as_slice()).expect("ecdh2");
        let k2 = s2
            .derive_session_keys(pb2.as_slice(), pa2.as_slice())
            .expect("derive swapped args");
        assert_eq!(k1.payload_key_i2r.as_ref(), k2.payload_key_i2r.as_ref());
    }
}
