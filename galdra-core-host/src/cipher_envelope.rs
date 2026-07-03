//! OpenPGP inner payload: profile-bound cascade ciphertext with session PRK and metadata.
//!
//! Optional **CESS Mode A** outer wrapping (ChaCha20-Poly1305 over `suite_id || inner_blob`) can be
//! applied around the GALDRACP bytes before OpenPGP encryption when `K_outer` and a nonce are known
//! (e.g. from ephemeral ECDH per CESS).

use crate::GaldraError;
use cess::{
    assemble_mode_a_outer_plaintext, open_mode_a_outer, parse_mode_a_outer_plaintext,
    seal_mode_a_outer, CessWireError,
};
use cipher_profile::{cascade_decrypt, cascade_encrypt, CascadeCiphertext, CipherProfile, CipherProfileError};
use galdr_core::legacy_removed::{self, MSG_CIPHERTEXT_HIGH_ASSURANCE, PROFILE_NAME_HIGH_ASSURANCE};
use rand::RngCore;

const MAGIC: &[u8; 8] = b"GALDRACP";
const VERSION: u8 = 1;

fn map_cipher_profile_err(e: CipherProfileError) -> GaldraError {
    match e {
        CipherProfileError::RemovedHighAssuranceProfile => {
            GaldraError::RemovedLegacyCrypto(MSG_CIPHERTEXT_HIGH_ASSURANCE.to_string())
        }
        CipherProfileError::RemovedBrainpoolP512Curve => {
            GaldraError::RemovedLegacyCrypto(legacy_removed::MSG_SESSION_CURVE_P512.to_string())
        }
        other => GaldraError::CipherProfile(format!("{other:?}")),
    }
}

fn map_cess_wire_err(e: CessWireError) -> GaldraError {
    match e {
        CessWireError::RemovedHighAssuranceSuite => {
            GaldraError::RemovedLegacyCrypto(MSG_CIPHERTEXT_HIGH_ASSURANCE.to_string())
        }
        other => GaldraError::CipherProfile(format!("cess outer plaintext: {other}")),
    }
}

/// Build AAD for cascade operations (must match encrypt and decrypt).
pub fn build_cipher_aad(profile_name: &str, sender_fingerprint_hex: &str, ts_unix: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(profile_name.as_bytes());
    v.push(b'|');
    v.extend_from_slice(sender_fingerprint_hex.as_bytes());
    v.push(b'|');
    v.extend_from_slice(&ts_unix.to_be_bytes());
    v
}

fn serialize_cascade_ct(ct: &CascadeCiphertext) -> Result<Vec<u8>, GaldraError> {
    let name = ct.profile_name.as_str().as_bytes();
    if name.len() > 64 {
        return Err(GaldraError::CipherProfile(
            "profile name too long".to_string(),
        ));
    }
    let mut out = Vec::new();
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    let body = ct.ciphertext.as_slice();
    let len = body.len();
    if len > 65536 {
        return Err(GaldraError::CipherProfile(
            "ciphertext too large".to_string(),
        ));
    }
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

fn deserialize_cascade_ct(data: &[u8]) -> Result<CascadeCiphertext, GaldraError> {
    if data.is_empty() {
        return Err(GaldraError::CipherProfile(
            "truncated cascade blob".to_string(),
        ));
    }
    let nl = data[0] as usize;
    if data.len() < 1 + nl + 4 {
        return Err(GaldraError::CipherProfile(
            "truncated cascade blob".to_string(),
        ));
    }
    let name_bytes = &data[1..1 + nl];
    let name_str = core::str::from_utf8(name_bytes)
        .map_err(|_| GaldraError::CipherProfile("invalid profile name utf8".to_string()))?;
    let mut i = 1 + nl;
    if data.len() < i + 4 {
        return Err(GaldraError::CipherProfile(
            "truncated cascade length".to_string(),
        ));
    }
    let cl = u32::from_be_bytes(
        data[i..i + 4]
            .try_into()
            .map_err(|_| GaldraError::CipherProfile("cascade inner len".to_string()))?,
    ) as usize;
    i += 4;
    if data.len() < i + cl {
        return Err(GaldraError::CipherProfile(
            "truncated cascade body".to_string(),
        ));
    }
    let ct_body = &data[i..i + cl];
    let mut profile_name = heapless::String::new();
    profile_name
        .push_str(name_str)
        .map_err(|_| GaldraError::CipherProfile("profile name buffer".to_string()))?;
    let mut ciphertext = heapless::Vec::new();
    for b in ct_body {
        ciphertext
            .push(*b)
            .map_err(|_| GaldraError::CipherProfile("ciphertext buffer".to_string()))?;
    }
    Ok(CascadeCiphertext {
        profile_name,
        ciphertext,
    })
}

/// Inner plaintext for OpenPGP: magic header, timestamp, sender fingerprint, PRK, cascade blob.
pub fn seal_plaintext_with_profile(
    profile: &CipherProfile,
    user_plaintext: &[u8],
    sender_fingerprint_hex: &str,
) -> Result<Vec<u8>, GaldraError> {
    if sender_fingerprint_hex.len() > 255 {
        return Err(GaldraError::CipherProfile(
            "sender fingerprint too long".to_string(),
        ));
    }
    let ts_unix = chrono::Utc::now().timestamp() as u64;
    let mut prk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut prk);
    let aad = build_cipher_aad(profile.name(), sender_fingerprint_hex, ts_unix);
    let cascade = cascade_encrypt(profile, &prk, &aad, user_plaintext)
        .map_err(|e| GaldraError::CipherProfile(format!("{e:?}")))?;
    let cascade_bytes = serialize_cascade_ct(&cascade)?;
    let fp = sender_fingerprint_hex.as_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC.as_slice());
    out.push(VERSION);
    out.extend_from_slice(&ts_unix.to_be_bytes());
    out.push(fp.len() as u8);
    out.extend_from_slice(fp);
    out.extend_from_slice(&prk);
    out.extend_from_slice(&(cascade_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&cascade_bytes);
    Ok(out)
}

/// Returns plaintext and the profile name used (from the inner blob).
pub fn open_plaintext_after_openpgp(
    inner: &[u8],
    get_profile: impl FnOnce(&str) -> Option<CipherProfile>,
) -> Result<(Vec<u8>, String), GaldraError> {
    if inner.len() < MAGIC.len() || &inner[..MAGIC.len()] != MAGIC.as_slice() {
        return Err(GaldraError::CipherProfile(
            "not a Galdra cipher-profile message (missing magic)".to_string(),
        ));
    }
    let mut i = MAGIC.len();
    if inner.len() < i + 1 {
        return Err(GaldraError::CipherProfile("truncated header".to_string()));
    }
    let ver = inner[i];
    i += 1;
    if ver != VERSION {
        return Err(GaldraError::CipherProfile(format!(
            "unsupported version {ver}"
        )));
    }
    if inner.len() < i + 8 {
        return Err(GaldraError::CipherProfile(
            "truncated timestamp".to_string(),
        ));
    }
    let ts_unix = u64::from_be_bytes(
        inner[i..i + 8]
            .try_into()
            .map_err(|_| GaldraError::CipherProfile("timestamp bytes".to_string()))?,
    );
    i += 8;
    if inner.len() < i + 1 {
        return Err(GaldraError::CipherProfile("truncated fp len".to_string()));
    }
    let fpl = inner[i] as usize;
    i += 1;
    if inner.len() < i + fpl {
        return Err(GaldraError::CipherProfile(
            "truncated fingerprint".to_string(),
        ));
    }
    let sender_fp = &inner[i..i + fpl];
    let sender_fp_str = core::str::from_utf8(sender_fp)
        .map_err(|_| GaldraError::CipherProfile("sender fingerprint utf8".to_string()))?;
    i += fpl;
    if inner.len() < i + 32 {
        return Err(GaldraError::CipherProfile("truncated prk".to_string()));
    }
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&inner[i..i + 32]);
    i += 32;
    if inner.len() < i + 4 {
        return Err(GaldraError::CipherProfile(
            "truncated cascade len".to_string(),
        ));
    }
    let cbl = u32::from_be_bytes(
        inner[i..i + 4]
            .try_into()
            .map_err(|_| GaldraError::CipherProfile("cascade len bytes".to_string()))?,
    ) as usize;
    i += 4;
    if inner.len() < i + cbl {
        return Err(GaldraError::CipherProfile(
            "truncated cascade blob".to_string(),
        ));
    }
    let cascade_raw = &inner[i..i + cbl];
    let cascade = deserialize_cascade_ct(cascade_raw)?;
    let pname = cascade.profile_name.as_str();
    if pname == PROFILE_NAME_HIGH_ASSURANCE {
        return Err(GaldraError::RemovedLegacyCrypto(
            MSG_CIPHERTEXT_HIGH_ASSURANCE.to_string(),
        ));
    }
    let pname = pname.to_string();
    let profile = get_profile(&pname).ok_or_else(|| GaldraError::ProfileNotFound(pname.clone()))?;
    let aad = build_cipher_aad(profile.name(), sender_fp_str, ts_unix);
    let plain = cascade_decrypt(&profile, &prk, &aad, &cascade).map_err(map_cipher_profile_err)?;
    Ok((plain.as_bytes().to_vec(), pname))
}

/// True if `data` begins with the Galdra cipher-profile inner magic.
pub fn is_cipher_profile_envelope(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC.as_slice()
}

/// Parse `s` as exactly `N` bytes of hex (length `2*N`).
pub fn parse_hex_fixed<const N: usize>(label: &str, s: &str) -> Result<[u8; N], GaldraError> {
    let s = s.trim();
    if s.len() != N * 2 {
        return Err(GaldraError::Config(format!(
            "{label} must be {} hex characters ({} bytes)",
            N * 2,
            N
        )));
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).map_err(|e| GaldraError::Config(format!("{label}: {e}")))?;
    Ok(out)
}

/// Wrap a sealed GALDRACP blob with CESS Mode A outer ChaCha20-Poly1305 (`nonce || ct || tag`).
///
/// `suite_id` is taken from the CESS [algorithm registry](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md)
/// lookup table for `profile_name`. Custom profiles without a mapping return an error until a suite id is assigned.
pub fn wrap_inner_with_cess_mode_a(
    inner_galdra: &[u8],
    profile_name: &str,
    k_outer: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, GaldraError> {
    let suite_id = cess::suite_id_for_profile_name(profile_name).ok_or_else(|| {
        GaldraError::CipherProfile(format!(
            "no CESS registry suite_id for profile '{profile_name}' (Mode A supports built-in profiles only)"
        ))
    })?;
    let outer_plain = assemble_mode_a_outer_plaintext(suite_id, inner_galdra)
        .map_err(|e| GaldraError::CipherProfile(format!("cess outer plaintext: {e}")))?;
    seal_mode_a_outer(k_outer, nonce, &outer_plain)
        .map_err(|e| GaldraError::CipherProfile(format!("cess Mode A seal: {e}")))
}

fn open_cess_mode_a_outer_to_inner_blob(
    wire: &[u8],
    k_outer: &[u8; 32],
) -> Result<Vec<u8>, GaldraError> {
    let plain = open_mode_a_outer(k_outer, wire)
        .map_err(|e| GaldraError::CipherProfile(format!("cess Mode A open: {e}")))?;
    let (_suite_id, inner) = parse_mode_a_outer_plaintext(&plain).map_err(map_cess_wire_err)?;
    Ok(inner.to_vec())
}

/// After OpenPGP yields the symmetric literal payload, recover user plaintext and profile name.
///
/// If the literal is not a GALDRACP envelope and `cess_k_outer` is set, the literal is treated as
/// CESS Mode A wire (`nonce || ct || tag`), opened with `K_outer`, then parsed as GALDRACP.
pub fn open_plaintext_from_openpgp_literal(
    inner: &[u8],
    cess_k_outer: Option<&[u8; 32]>,
    get_profile: impl FnOnce(&str) -> Option<CipherProfile>,
) -> Result<(Vec<u8>, String), GaldraError> {
    if is_cipher_profile_envelope(inner) {
        return open_plaintext_after_openpgp(inner, get_profile);
    }
    if let Some(k) = cess_k_outer {
        let blob = open_cess_mode_a_outer_to_inner_blob(inner, k)?;
        if !is_cipher_profile_envelope(&blob) {
            return Err(GaldraError::CipherProfile(
                "CESS outer decrypted but inner is not a Galdra cipher-profile envelope"
                    .to_string(),
            ));
        }
        return open_plaintext_after_openpgp(&blob, get_profile);
    }
    Ok((inner.to_vec(), "legacy-openpgp".to_string()))
}

#[cfg(test)]
mod cess_wrap_tests {
    use super::*;

    #[test]
    fn cess_mode_a_roundtrip_wraps_galdra_inner() {
        let k_outer = [9u8; 32];
        let nonce = [1u8; 12];
        let inner = b"GALDRACPfake-for-test";
        let wire = wrap_inner_with_cess_mode_a(inner, "standard", &k_outer, &nonce).expect("wrap");
        let back = super::open_cess_mode_a_outer_to_inner_blob(&wire, &k_outer).expect("open");
        assert_eq!(back.as_slice(), inner.as_slice());
    }

    #[test]
    fn high_assurance_profile_name_in_blob_rejected() {
        let name = PROFILE_NAME_HIGH_ASSURANCE.as_bytes();
        let mut cascade_bytes = Vec::new();
        cascade_bytes.push(name.len() as u8);
        cascade_bytes.extend_from_slice(name);
        cascade_bytes.extend_from_slice(&0u32.to_be_bytes());
        let mut inner = Vec::new();
        inner.extend_from_slice(b"GALDRACP");
        inner.push(1);
        inner.extend_from_slice(&0u64.to_be_bytes());
        inner.push(0);
        inner.extend_from_slice(&[0u8; 32]);
        inner.extend_from_slice(&(cascade_bytes.len() as u32).to_be_bytes());
        inner.extend_from_slice(&cascade_bytes);
        let err = open_plaintext_after_openpgp(&inner, |_| None).unwrap_err();
        assert!(matches!(err, GaldraError::RemovedLegacyCrypto(_)));
        assert_eq!(
            err.to_string(),
            MSG_CIPHERTEXT_HIGH_ASSURANCE.to_string()
        );
    }

    #[test]
    fn cess_suite_id_high_assurance_rejected_on_open() {
        let k_outer = [9u8; 32];
        let nonce = [1u8; 12];
        let inner = b"GALDRACPfake";
        let plain =
            assemble_mode_a_outer_plaintext(legacy_removed::CESS_SUITE_ID_HIGH_ASSURANCE, inner)
                .unwrap_err();
        assert!(matches!(
            plain,
            CessWireError::RemovedHighAssuranceSuite
        ));
        let _ = (k_outer, nonce);
    }
}
