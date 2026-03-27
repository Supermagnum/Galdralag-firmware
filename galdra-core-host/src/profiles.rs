//! Host-side cipher profile registry backed by `cipher_profile::ProfileRegistry` and SQLite.

use crate::db::Db;
use crate::GaldraError;
use chrono::Utc;
use cipher_profile::{
    curve_audit_str, layer_audit_name, CipherProfile, CipherProfileBuilder, CipherProfileError,
    CipherLayer, ProfileRegistry, ShamirConfig,
};
use ephemeral_session::SessionCurve;
use rusqlite::params;

/// Names that are always present and cannot be removed.
pub const BUILTIN_PROFILE_NAMES: &[&str] = &[
    "standard",
    "conservative",
    "conservative-shamir",
    "high-assurance",
];

fn map_cipher_err(e: CipherProfileError) -> GaldraError {
    GaldraError::CipherProfile(format!("{e:?}"))
}

/// Host-side wrapper for the cipher profile registry.
pub struct ProfileStore {
    registry: ProfileRegistry,
}

impl ProfileStore {
    /// Load built-in profiles and user rows from `user_profiles`.
    pub fn load(db: &Db) -> Result<Self, GaldraError> {
        let mut registry = ProfileRegistry::with_builtins();
        let mut stmt = db
            .connection()
            .prepare("SELECT serialised FROM user_profiles ORDER BY name")
            .map_err(GaldraError::Database)?;
        let mut rows = stmt.query([]).map_err(GaldraError::Database)?;
        while let Some(row) = rows.next().map_err(GaldraError::Database)? {
            let blob: Vec<u8> = row.get(0).map_err(GaldraError::Database)?;
            let p = CipherProfile::from_bytes(&blob).map_err(map_cipher_err)?;
            registry.register(p).map_err(map_cipher_err)?;
        }
        Ok(Self { registry })
    }

    /// List all profiles (built-ins and user-defined).
    pub fn list(&self) -> Vec<ProfileSummary> {
        let mut out = Vec::new();
        for name in self.registry.list() {
            if let Some(p) = self.registry.get(name) {
                out.push(ProfileSummary::from_profile(p, self.is_builtin(name)));
            }
        }
        out
    }

    /// Look up by name.
    pub fn get(&self, name: &str) -> Option<&CipherProfile> {
        self.registry.get(name)
    }

    /// Clone profile by name (for cascade operations).
    pub fn get_owned(&self, name: &str) -> Option<CipherProfile> {
        self.get(name).cloned()
    }

    /// True if the name is a built-in profile.
    pub fn is_builtin(&self, name: &str) -> bool {
        BUILTIN_PROFILE_NAMES.contains(&name)
    }

    /// Add a user profile and persist.
    pub fn add(&mut self, db: &mut Db, profile: CipherProfile) -> Result<(), GaldraError> {
        let name = profile.name().to_string();
        let desc = profile.description().to_string();
        let blob = profile.to_bytes();
        self.registry
            .register(profile)
            .map_err(map_cipher_err)?;
        match insert_user_row(db, &name, &desc, &blob) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = self.registry.remove(&name);
                Err(e)
            }
        }
    }

    /// Remove a user-defined profile.
    pub fn remove(&mut self, db: &mut Db, name: &str) -> Result<(), GaldraError> {
        self.registry.remove(name).map_err(map_cipher_err)?;
        db.connection_mut()
            .execute(
                "DELETE FROM user_profiles WHERE name = ?1",
                params![name],
            )
            .map_err(GaldraError::Database)?;
        Ok(())
    }
}

fn insert_user_row(db: &mut Db, name: &str, desc: &str, blob: &[u8]) -> Result<(), GaldraError> {
    let now = Utc::now().to_rfc3339();
    db.connection_mut()
        .execute(
            "INSERT INTO user_profiles (name, description, serialised, created_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![name, desc, blob, now, None::<String>],
        )
        .map_err(GaldraError::Database)?;
    Ok(())
}

/// Summary row for CLI / GUI / REST.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProfileSummary {
    pub name: String,
    pub description: String,
    pub curve: String,
    pub layers: Vec<String>,
    pub shamir_k: u8,
    pub shamir_n: u8,
    pub is_builtin: bool,
}

impl ProfileSummary {
    pub fn from_profile(p: &CipherProfile, is_builtin: bool) -> Self {
        let mut layers = Vec::new();
        for layer in p.layers() {
            layers.push(layer_audit_name(*layer).to_string());
        }
        let sham = p.shamir();
        ProfileSummary {
            name: p.name().to_string(),
            description: p.description().to_string(),
            curve: curve_audit_str(p.curve()).to_string(),
            layers,
            shamir_k: sham.threshold,
            shamir_n: sham.total,
            is_builtin,
        }
    }
}

/// Parse curve string for `galdra profile add` / REST.
pub fn parse_curve_wire(s: &str) -> Result<SessionCurve, GaldraError> {
    match s.to_ascii_lowercase().as_str() {
        "brainpool256" | "bp256" | "brainpoolp256r1" => Ok(SessionCurve::BrainpoolP256r1),
        "brainpool384" | "bp384" | "brainpoolp384r1" => Ok(SessionCurve::BrainpoolP384r1),
        "brainpool512" | "bp512" | "brainpoolp512r1" => Ok(SessionCurve::BrainpoolP512r1),
        _ => Err(GaldraError::Config(format!("unknown curve: {s}"))),
    }
}

/// Parse layer name for CLI.
pub fn parse_layer_name(s: &str) -> Result<CipherLayer, GaldraError> {
    match s.to_ascii_lowercase().as_str() {
        "aes256gcm" => Ok(CipherLayer::Aes256Gcm),
        "chacha20poly1305" => Ok(CipherLayer::ChaCha20Poly1305),
        "twofish256" => Ok(CipherLayer::Twofish256),
        "serpent256" => Ok(CipherLayer::Serpent256),
        _ => Err(GaldraError::Config(format!("unknown cipher layer: {s}"))),
    }
}

/// Single-line audit detail for encrypt/decrypt actions (no secrets).
pub fn audit_crypto_detail_line(
    profile: &CipherProfile,
    recipients: usize,
    session_id: &str,
) -> String {
    let mut layers = Vec::new();
    for layer in profile.layers() {
        layers.push(layer_audit_name(*layer).to_string());
    }
    let sham = profile.shamir();
    let sham_s = if sham.is_active() {
        format!("{}/{}", sham.threshold, sham.total)
    } else {
        "none".to_string()
    };
    format!(
        "profile:{} curve:{} layers:[{}] shamir:{} recipients:{} session_id:{}",
        profile.name(),
        curve_audit_str(profile.curve()),
        layers.join(", "),
        sham_s,
        recipients,
        session_id
    )
}

/// Multi-line audit detail (for human-readable `galdra audit show` output).
pub fn audit_crypto_detail_multiline(
    profile: &CipherProfile,
    recipients: usize,
    session_id: &str,
) -> String {
    let mut layers = Vec::new();
    for layer in profile.layers() {
        layers.push(layer_audit_name(*layer).to_string());
    }
    let sham = profile.shamir();
    let sham_s = if sham.is_active() {
        format!("{}/{}", sham.threshold, sham.total)
    } else {
        "none".to_string()
    };
    format!(
        "profile:{}\ncurve:{}  layers:[{}]  shamir:{}\nrecipients:{}  session_id:{}",
        profile.name(),
        curve_audit_str(profile.curve()),
        layers.join(", "),
        sham_s,
        recipients,
        session_id
    )
}

/// Build a profile from CLI / REST pieces.
pub fn build_profile_from_options(
    name: &str,
    description: &str,
    curve: SessionCurve,
    layers: &[CipherLayer],
    shamir_threshold: u8,
    shamir_total: u8,
) -> Result<CipherProfile, GaldraError> {
    let mut b = CipherProfileBuilder::new(name).map_err(map_cipher_err)?;
    b = b.description(description).curve(curve);
    for layer in layers {
        b = b.layer(*layer).map_err(map_cipher_err)?;
    }
    let sham = ShamirConfig::new(shamir_threshold, shamir_total).map_err(map_cipher_err)?;
    b = b.shamir(sham);
    b.build().map_err(map_cipher_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_store_load_builtins() {
        let db = Db::open_in_memory().expect("db");
        let store = ProfileStore::load(&db).expect("load");
        for n in BUILTIN_PROFILE_NAMES {
            assert!(store.get(n).is_some(), "missing {n}");
        }
    }

    #[test]
    fn test_profile_store_add_persist() {
        let path = tempfile::NamedTempFile::new().expect("tmp");
        let path = path.path().to_path_buf();
        {
            let mut db = Db::open(&path, None).expect("db");
            let mut store = ProfileStore::load(&db).expect("load");
            let p = build_profile_from_options(
                "u-test",
                "d",
                SessionCurve::BrainpoolP256r1,
                &[CipherLayer::ChaCha20Poly1305],
                1,
                1,
            )
            .expect("build");
            store.add(&mut db, p).expect("add");
        }
        let db2 = Db::open(&path, None).expect("db2");
        let store2 = ProfileStore::load(&db2).expect("load2");
        assert!(store2.get("u-test").is_some());
    }

    #[test]
    fn test_profile_store_remove_builtin() {
        let db = Db::open_in_memory().expect("db");
        let mut store = ProfileStore::load(&db).expect("load");
        let mut db = db;
        let r = store.remove(&mut db, "standard");
        assert!(r.is_err());
    }
}
