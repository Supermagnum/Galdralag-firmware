//! OpenPGP inner payload: profile-bound cascade ciphertext with session PRK and metadata.

use crate::GaldraError;
use cipher_profile::{
    cascade_decrypt, cascade_encrypt, CascadeCiphertext, CipherProfile,
};
use rand::RngCore;

const MAGIC: &[u8; 8] = b"GALDRACP";
const VERSION: u8 = 1;

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
        return Err(GaldraError::CipherProfile("profile name too long".to_string()));
    }
    let mut out = Vec::new();
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    let body = ct.ciphertext.as_slice();
    let len = body.len();
    if len > 65536 {
        return Err(GaldraError::CipherProfile("ciphertext too large".to_string()));
    }
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

fn deserialize_cascade_ct(data: &[u8]) -> Result<CascadeCiphertext, GaldraError> {
    if data.is_empty() {
        return Err(GaldraError::CipherProfile("truncated cascade blob".to_string()));
    }
    let nl = data[0] as usize;
    if data.len() < 1 + nl + 4 {
        return Err(GaldraError::CipherProfile("truncated cascade blob".to_string()));
    }
    let name_bytes = &data[1..1 + nl];
    let name_str = core::str::from_utf8(name_bytes)
        .map_err(|_| GaldraError::CipherProfile("invalid profile name utf8".to_string()))?;
    let mut i = 1 + nl;
    if data.len() < i + 4 {
        return Err(GaldraError::CipherProfile("truncated cascade length".to_string()));
    }
    let cl = u32::from_be_bytes(
        data[i..i + 4]
            .try_into()
            .map_err(|_| GaldraError::CipherProfile("cascade inner len".to_string()))?,
    ) as usize;
    i += 4;
    if data.len() < i + cl {
        return Err(GaldraError::CipherProfile("truncated cascade body".to_string()));
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
        return Err(GaldraError::CipherProfile(format!("unsupported version {ver}")));
    }
    if inner.len() < i + 8 {
        return Err(GaldraError::CipherProfile("truncated timestamp".to_string()));
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
        return Err(GaldraError::CipherProfile("truncated fingerprint".to_string()));
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
        return Err(GaldraError::CipherProfile("truncated cascade len".to_string()));
    }
    let cbl = u32::from_be_bytes(
        inner[i..i + 4]
            .try_into()
            .map_err(|_| GaldraError::CipherProfile("cascade len bytes".to_string()))?,
    ) as usize;
    i += 4;
    if inner.len() < i + cbl {
        return Err(GaldraError::CipherProfile("truncated cascade blob".to_string()));
    }
    let cascade_raw = &inner[i..i + cbl];
    let cascade = deserialize_cascade_ct(cascade_raw)?;
    let pname = cascade.profile_name.as_str().to_string();
    let profile = get_profile(&pname)
        .ok_or_else(|| GaldraError::ProfileNotFound(pname.clone()))?;
    let aad = build_cipher_aad(profile.name(), sender_fp_str, ts_unix);
    let plain = cascade_decrypt(&profile, &prk, &aad, &cascade)
        .map_err(|e| GaldraError::CipherProfile(format!("{e:?}")))?;
    Ok((plain.as_bytes().to_vec(), pname))
}

/// True if `data` begins with the Galdra cipher-profile inner magic.
pub fn is_cipher_profile_envelope(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC.as_slice()
}
