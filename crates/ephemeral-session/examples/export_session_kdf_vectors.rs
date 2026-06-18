//! Emit JSON session KDF vectors for gr-linux-crypto cross-verification.
//!
//! Run from Galdralag-firmware workspace root:
//!   cargo run -p ephemeral-session --example export_session_kdf_vectors

use ephemeral_session::domain;
use ephemeral_session::{EphemeralKeyPair, SessionCurve};
use galdr_core::fake_hal::FakeTrng;
use galdr_vault::brainpool::BrainpoolScalar;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

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

fn ordered_epk_salt(epk_initiator: &[u8], epk_responder: &[u8]) -> Vec<u8> {
    let mut salt = Vec::new();
    if epk_initiator <= epk_responder {
        salt.extend_from_slice(epk_initiator);
        salt.extend_from_slice(epk_responder);
    } else {
        salt.extend_from_slice(epk_responder);
        salt.extend_from_slice(epk_initiator);
    }
    salt
}

fn expand_key(prk: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("prk");
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("expand");
    out
}

fn export_p256_seed_7_8() -> serde_json::Value {
    let mut t1 = FakeTrng::from_seed(7);
    let mut t2 = FakeTrng::from_seed(8);
    let curve = SessionCurve::BrainpoolP256r1;

    let sk_a = BrainpoolScalar::generate(&mut t1).expect("sk_a");
    let sk_b = BrainpoolScalar::generate(&mut t2).expect("sk_b");
    let pk_a = sk_a.public_key().expect("pk_a");
    let pk_b = sk_b.public_key().expect("pk_b");
    let pa = pk_a.to_sec1_uncompressed();
    let pb = pk_b.to_sec1_uncompressed();
    let ikm = sk_a
        .diffie_hellman(&pk_b)
        .expect("ecdh")
        .as_bytes()
        .to_vec();

    let mut t3 = FakeTrng::from_seed(7);
    let mut t4 = FakeTrng::from_seed(8);
    let a = EphemeralKeyPair::generate(curve, &mut t3).expect("a");
    let b = EphemeralKeyPair::generate(curve, &mut t4).expect("b");
    let pa_ep = a.public_key_bytes();
    let pb_ep = b.public_key_bytes();
    assert_eq!(pa_ep, pa.as_slice());
    assert_eq!(pb_ep, pb.as_slice());

    let salt = ordered_epk_salt(pa_ep, pb_ep);
    let prk = hkdf_extract_sha256(&salt, &ikm);

    json!({
        "description": "FakeTrng seeds 7 (initiator) and 8 (responder), BrainpoolP256r1",
        "curve": "brainpoolP256r1",
        "initiator_seed": 7,
        "responder_seed": 8,
        "initiator_scalar_hex": hex::encode(sk_a.to_secret_bytes_for_test()),
        "responder_scalar_hex": hex::encode(sk_b.to_secret_bytes_for_test()),
        "epk_initiator_hex": hex::encode(pa_ep),
        "epk_responder_hex": hex::encode(pb_ep),
        "ecdh_ikm_hex": hex::encode(&ikm),
        "profile_prk_hex": hex::encode(prk),
        "payload_key_i2r_hex": hex::encode(expand_key(&prk, domain::PAYLOAD_KEY_I2R)),
        "payload_key_r2i_hex": hex::encode(expand_key(&prk, domain::PAYLOAD_KEY_R2I)),
        "gdss_mask_key_hex": hex::encode(expand_key(&prk, domain::GDSS_MASK_KEY)),
        "gdss_sync_key_hex": hex::encode(expand_key(&prk, domain::GDSS_SYNC_KEY)),
        "gdss_timing_key_hex": hex::encode(expand_key(&prk, domain::GDSS_TIMING_KEY)),
        "mac_key_hex": hex::encode(expand_key(&prk, domain::MAC_KEY)),
    })
}

fn main() {
    let out = json!({
        "source": "Galdralag-firmware ephemeral-session",
        "vectors": [export_p256_seed_7_8()],
    });
    println!("{}", serde_json::to_string_pretty(&out).expect("json"));
}
