//! Shamir share export and token-assisted split/recover (host orchestration).

use crate::device::Device;
use crate::GaldraError;
use chrono::Utc;
use cipher_profile::CipherProfile;
use galdr_core::fake_hal::FakeTrng;
use std::fmt::Write as _;
use galdr_vault::shamir::{shamir_recover, shamir_split, ShamirError, ShamirShare};
use zeroize::Zeroize;

fn map_shamir_err(e: ShamirError) -> GaldraError {
    GaldraError::Shamir(format!("{e:?}"))
}

#[cfg(test)]
thread_local! {
    static ZEROISING_SHARE_DROP_HOOK: std::cell::Cell<u32> = std::cell::Cell::new(0);
}

/// A single exported Shamir share for distribution.
pub struct ShamirShareExport {
    /// Profile whose Shamir parameters were used.
    pub profile_name: String,
    /// Threshold K (minimum shares to recover).
    pub threshold: u8,
    /// Total shares N.
    pub total: u8,
    /// Share index (1-based).
    pub index: u8,
    /// Raw share bytes (zeroised on drop).
    pub value: ZeroizingShareBytes,
    /// Hex fingerprint of the long-term key material this share belongs to.
    pub fingerprint: String,
    /// Creation time for display.
    pub created_at_rfc3339: String,
}

/// Holds share bytes and zeroises them on drop.
pub struct ZeroizingShareBytes(Vec<u8>);

impl ZeroizingShareBytes {
    /// Borrow share bytes (sensitive).
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Drop for ZeroizingShareBytes {
    fn drop(&mut self) {
        #[cfg(test)]
        ZEROISING_SHARE_DROP_HOOK.with(|c| c.set(c.get().saturating_add(1)));
        self.0.zeroize();
    }
}

impl ShamirShareExport {
    /// ASCII armour suitable for files and QR payloads.
    pub fn to_armoured(&self) -> String {
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            self.value.as_slice(),
        );
        let mut s = String::new();
        let _ = writeln!(s, "-----BEGIN GALDRA SHARE-----");
        let _ = writeln!(s, "Version: 1");
        let _ = writeln!(s, "Profile: {}", self.profile_name);
        let _ = writeln!(s, "Threshold: {}", self.threshold);
        let _ = writeln!(s, "Total: {}", self.total);
        let _ = writeln!(s, "Index: {}", self.index);
        let _ = writeln!(s, "Fingerprint: {}", self.fingerprint);
        let _ = writeln!(s, "Created: {}", self.created_at_rfc3339);
        let _ = writeln!(s);
        let _ = writeln!(s, "{b64}");
        let _ = writeln!(s, "-----END GALDRA SHARE-----");
        s
    }

    /// Parse armour produced by [`Self::to_armoured`].
    pub fn from_armoured(text: &str) -> Result<Self, GaldraError> {
        let mut profile_name: Option<String> = None;
        let mut threshold: Option<u8> = None;
        let mut total: Option<u8> = None;
        let mut index: Option<u8> = None;
        let mut fingerprint: Option<String> = None;
        let mut created: Option<String> = None;
        let mut in_body = false;
        let mut b64_lines: Vec<String> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line == "-----BEGIN GALDRA SHARE-----" {
                continue;
            }
            if line == "-----END GALDRA SHARE-----" {
                break;
            }
            if line.is_empty() {
                in_body = true;
                continue;
            }
            if let Some(rest) = line.strip_prefix("Profile:") {
                profile_name = Some(rest.trim().to_string());
                continue;
            }
            if let Some(rest) = line.strip_prefix("Threshold:") {
                threshold = Some(
                    rest.trim()
                        .parse()
                        .map_err(|_| GaldraError::Shamir("invalid Threshold".to_string()))?,
                );
                continue;
            }
            if let Some(rest) = line.strip_prefix("Total:") {
                total = Some(
                    rest.trim()
                        .parse()
                        .map_err(|_| GaldraError::Shamir("invalid Total".to_string()))?,
                );
                continue;
            }
            if let Some(rest) = line.strip_prefix("Index:") {
                index = Some(
                    rest.trim()
                        .parse()
                        .map_err(|_| GaldraError::Shamir("invalid Index".to_string()))?,
                );
                continue;
            }
            if let Some(rest) = line.strip_prefix("Fingerprint:") {
                fingerprint = Some(rest.trim().to_string());
                continue;
            }
            if let Some(rest) = line.strip_prefix("Created:") {
                created = Some(rest.trim().to_string());
                continue;
            }
            if line.starts_with("Version:") {
                continue;
            }
            if in_body || (!line.contains(':') && !line.is_empty()) {
                b64_lines.push(line.to_string());
            }
        }
        let pn = profile_name.ok_or_else(|| GaldraError::Shamir("missing Profile".to_string()))?;
        let thr = threshold.unwrap_or(1);
        let tot = total.unwrap_or(1);
        let idx = index.ok_or_else(|| GaldraError::Shamir("missing Index".to_string()))?;
        let fp = fingerprint.unwrap_or_default();
        let cr = created.unwrap_or_else(|| Utc::now().to_rfc3339());
        let concat: String = b64_lines.join("");
        let raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            concat.as_str().trim(),
        )
        .map_err(|e| GaldraError::Shamir(format!("base64: {e}")))?;
        Ok(ShamirShareExport {
            profile_name: pn,
            threshold: thr,
            total: tot,
            index: idx,
            value: ZeroizingShareBytes(raw),
            fingerprint: fp,
            created_at_rfc3339: cr,
        })
    }
}

/// Split the long-term key in `slot` using `profile` Shamir parameters (requires token + unlock).
pub fn shamir_split_key(
    device: &Device,
    profile: &CipherProfile,
    slot: u32,
) -> Result<Vec<ShamirShareExport>, GaldraError> {
    let _st = device.status()?;
    let sham = profile.shamir();
    if !sham.is_active() {
        return Err(GaldraError::Config(
            "profile does not enable Shamir (total must be > 1)".to_string(),
        ));
    }
    let mut secret = device.export_signing_key_shamir_material(slot)?;
    let k = sham.threshold;
    let n = sham.total;
    let mut trng = FakeTrng::from_seed(0x5F4D_414D_4952u64);
    let share_vec = shamir_split(secret.as_slice(), k, n, &mut trng).map_err(map_shamir_err)?;
    let fp = device.signing_key_fingerprint_hex(slot)?;
    let created = Utc::now().to_rfc3339();
    let mut out = Vec::new();
    for sh in share_vec.iter() {
        let mut v = Vec::new();
        v.extend_from_slice(sh.value());
        out.push(ShamirShareExport {
            profile_name: profile.name().to_string(),
            threshold: k,
            total: n,
            index: sh.index,
            value: ZeroizingShareBytes(v),
            fingerprint: fp.clone(),
            created_at_rfc3339: created.clone(),
        });
    }
    secret.zeroize();
    Ok(out)
}

/// Recover a key from shares and import into `slot`. Uses `threshold` from each share header.
pub fn shamir_recover_key(
    device: &Device,
    shares: &[ShamirShareExport],
    slot: u32,
) -> Result<(), GaldraError> {
    let _st = device.status()?;
    if shares.is_empty() {
        return Err(GaldraError::Shamir(
            "insufficient shares for recovery".to_string(),
        ));
    }
    let k = shares[0].threshold;
    if k == 0 {
        return Err(GaldraError::Shamir("invalid threshold".to_string()));
    }
    if (shares.len() as u8) < k {
        return Err(GaldraError::Shamir(
            "insufficient shares for recovery".to_string(),
        ));
    }
    let mut vault_shares: Vec<ShamirShare> = Vec::new();
    for ex in shares.iter().take(usize::from(k)) {
        let s = ShamirShare::try_from_index_value(ex.index, ex.value.as_slice())
            .map_err(map_shamir_err)?;
        vault_shares.push(s);
    }
    let recovered = shamir_recover(&vault_shares, k).map_err(map_shamir_err)?;
    let buf = recovered.as_slice();
    if buf.len() != 32 {
        return Err(GaldraError::Shamir(
            "recovered secret length unexpected".to_string(),
        ));
    }
    let mut material = [0u8; 32];
    material.copy_from_slice(buf);
    device.import_shamir_recovered_signing_key(slot, &material)?;
    material.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_share_value_zeroised_on_drop() {
        let before = ZEROISING_SHARE_DROP_HOOK.with(|c| c.get());
        let ex = ShamirShareExport {
            profile_name: "p".to_string(),
            threshold: 2,
            total: 3,
            index: 1,
            value: ZeroizingShareBytes(vec![9u8; 32]),
            fingerprint: "ab".to_string(),
            created_at_rfc3339: "2020-01-01T00:00:00Z".to_string(),
        };
        drop(ex);
        let after = ZEROISING_SHARE_DROP_HOOK.with(|c| c.get());
        assert_eq!(after - before, 1);
    }

    #[test]
    fn test_shamir_share_export_armour_roundtrip() {
        let ex = ShamirShareExport {
            profile_name: "p".to_string(),
            threshold: 2,
            total: 3,
            index: 2,
            value: ZeroizingShareBytes(vec![1u8; 32]),
            fingerprint: "ab:cd".to_string(),
            created_at_rfc3339: "2020-01-01T00:00:00Z".to_string(),
        };
        let arm = ex.to_armoured();
        let p2 = ShamirShareExport::from_armoured(&arm).expect("parse");
        assert_eq!(p2.profile_name, "p");
        assert_eq!(p2.threshold, 2);
        assert_eq!(p2.total, 3);
        assert_eq!(p2.index, 2);
        assert_eq!(p2.value.as_slice(), &[1u8; 32]);
        assert_eq!(p2.fingerprint, "ab:cd");
    }
}
