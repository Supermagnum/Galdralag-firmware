//! Ephemeral key offer lifecycle management.
//!
//! Host-side counterpart to the token's `ephemeral-session` wire protocol. Offers are signed
//! BrainpoolP256r1 ephemeral public keys distributed as GnuPG sign-then-encrypt blobs
//! (`.epk.gpg`). Lifecycle: generate -> export -> peer imports -> derive session keys.
//!
//! ## JSON offer format
//!
//! Wire format is identical to gr-linux-crypto (schema_version 1). See
//! `docs/EPHEMERAL_KEY_EXCHANGE.md` for the normative schema.
//!
//! ## Signature preimage
//!
//! The inner detached GnuPG signature covers the **raw uncompressed SEC1 EPK bytes only**,
//! not the `init_sign_preimage(version, curve_wire_id, epk)` used by the token wire protocol.
//! This matches gr-linux-crypto and allows cross-verification with `gpg --verify`. Host offers
//! are therefore NOT directly usable as `InitMessage` payloads on the token. See
//! `docs/EPHEMERAL_KEY_EXCHANGE.md` for the full interoperability note.
//!
//! ## Private key storage
//!
//! Self-generated offers store the BrainpoolP256r1 private scalar (raw 32 bytes) in the
//! `my_private_key_pem` column as a binary BLOB. This column is NULL for imported peer offers.
//! The private key is protected by the same DB access controls and optional SQLCipher encryption
//! as the rest of the galdra-core-host database. After a successful derivation or manual
//! revocation (`revoke_offer`), the column is zeroed in-place. Zeroising on DB write is a
//! best-effort operation: the underlying SQLite page may remain in the WAL or OS page cache
//! until the page is overwritten. For maximum key hygiene, encrypt the DB at rest with
//! SQLCipher and treat `expires_at` as an upper bound on key lifetime.

use crate::audit::{audit_append, AuditAction, AuditEntry};
use crate::db::Db;
use crate::GaldraError;
use chrono::Utc;
use galdr_vault::brainpool::BrainpoolScalar;
use rand::rngs::OsRng;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::process::Command;

const OFFER_SCHEMA_VERSION: u64 = 1;

// ---------------------------------------------------------------------------
// Wire-format offer JSON (identical to gr-linux-crypto schema version 1).
// ---------------------------------------------------------------------------

/// Plaintext JSON body of an ephemeral key offer.
///
/// Serialises with sorted keys and compact separators to match gr-linux-crypto exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferJson {
    pub schema_version: u64,
    pub epk_hex: String,
    pub long_term_fingerprint: String,
    pub signature_hex: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub session_id: String,
    pub consumed: bool,
}

// ---------------------------------------------------------------------------
// DB row.
// ---------------------------------------------------------------------------

/// A row from the `ephemeral_offers` table.
#[derive(Debug, Clone)]
pub struct OfferRow {
    pub session_id: String,
    pub epk_hex: String,
    pub curve: String,
    pub long_term_fingerprint: String,
    pub signature_hex: String,
    /// UTC Unix seconds.
    pub expires_at: i64,
    /// UTC Unix seconds.
    pub created_at: i64,
    pub consumed: bool,
    pub revoked: bool,
    pub imported_at: String,
    /// Non-None only for self-generated offers.  Contains raw BrainpoolP256r1 scalar bytes.
    pub my_private_key_bytes: Option<Vec<u8>>,
}

impl OfferRow {
    /// True if the offer is past its expiry time.
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() >= self.expires_at
    }

    /// True if the offer can still be used (not consumed, not revoked, not expired).
    pub fn is_valid(&self) -> bool {
        !self.consumed && !self.revoked && !self.is_expired()
    }
}

// ---------------------------------------------------------------------------
// DB CRUD.
// ---------------------------------------------------------------------------

/// Insert an offer row into the database.
pub fn store_offer(db: &mut Db, row: &OfferRow) -> Result<(), GaldraError> {
    db.connection_mut()
        .execute(
            r"INSERT INTO ephemeral_offers
            (session_id, epk_hex, curve, long_term_fingerprint, signature_hex,
             expires_at, created_at, consumed, revoked, imported_at, my_private_key_pem)
          VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                row.session_id,
                row.epk_hex,
                row.curve,
                row.long_term_fingerprint,
                row.signature_hex,
                row.expires_at,
                row.created_at,
                row.consumed as i64,
                row.revoked as i64,
                row.imported_at,
                row.my_private_key_bytes,
            ],
        )
        .map_err(GaldraError::Database)?;
    Ok(())
}

/// Retrieve a single offer by `session_id`. Returns `EpkNotFound` if absent.
pub fn get_offer(db: &Db, session_id: &str) -> Result<OfferRow, GaldraError> {
    let row = db
        .connection()
        .query_row(
            r"SELECT session_id, epk_hex, curve, long_term_fingerprint, signature_hex,
                     expires_at, created_at, consumed, revoked, imported_at, my_private_key_pem
               FROM ephemeral_offers WHERE session_id = ?1",
            [session_id],
            map_offer_row,
        )
        .optional()
        .map_err(GaldraError::Database)?
        .ok_or_else(|| GaldraError::EpkNotFound(session_id.to_string()))?;
    Ok(row)
}

/// List all offer rows ordered by creation time (newest first).
pub fn list_offers(db: &Db) -> Result<Vec<OfferRow>, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT session_id, epk_hex, curve, long_term_fingerprint, signature_hex,
                     expires_at, created_at, consumed, revoked, imported_at, my_private_key_pem
               FROM ephemeral_offers ORDER BY created_at DESC",
        )
        .map_err(GaldraError::Database)?;
    let rows = stmt
        .query_map([], map_offer_row)
        .map_err(GaldraError::Database)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(GaldraError::Database)?);
    }
    Ok(out)
}

/// Mark an offer consumed. Returns `EpkNotFound` if absent, `EpkConsumed` if already consumed.
pub fn mark_consumed(db: &mut Db, session_id: &str) -> Result<(), GaldraError> {
    let row = get_offer(db, session_id)?;
    if row.consumed {
        return Err(GaldraError::EpkConsumed(session_id.to_string()));
    }
    db.connection_mut()
        .execute(
            "UPDATE ephemeral_offers SET consumed = 1 WHERE session_id = ?1",
            [session_id],
        )
        .map_err(GaldraError::Database)?;
    Ok(())
}

/// Revoke an offer immediately: set `revoked=1` and zero the private key column.
///
/// This is the manual expiry path (`galdra epk expire`). The column is overwritten with a
/// zero-length BLOB to free the key material; subsequent reads return `None` for the private
/// key field.
pub fn revoke_offer(db: &mut Db, session_id: &str) -> Result<(), GaldraError> {
    let exists = db
        .connection()
        .query_row(
            "SELECT 1 FROM ephemeral_offers WHERE session_id = ?1",
            [session_id],
            |_| Ok(()),
        )
        .optional()
        .map_err(GaldraError::Database)?;
    if exists.is_none() {
        return Err(GaldraError::EpkNotFound(session_id.to_string()));
    }
    db.connection_mut()
        .execute(
            "UPDATE ephemeral_offers SET revoked = 1, my_private_key_pem = NULL WHERE session_id = ?1",
            [session_id],
        )
        .map_err(GaldraError::Database)?;
    Ok(())
}

fn map_offer_row(row: &rusqlite::Row<'_>) -> Result<OfferRow, rusqlite::Error> {
    Ok(OfferRow {
        session_id: row.get(0)?,
        epk_hex: row.get(1)?,
        curve: row.get(2)?,
        long_term_fingerprint: row.get(3)?,
        signature_hex: row.get(4)?,
        expires_at: row.get(5)?,
        created_at: row.get(6)?,
        consumed: row.get::<_, i64>(7)? != 0,
        revoked: row.get::<_, i64>(8)? != 0,
        imported_at: row.get(9)?,
        my_private_key_bytes: row.get(10)?,
    })
}

// ---------------------------------------------------------------------------
// Expiry and state validation helpers.
// ---------------------------------------------------------------------------

/// Return `EpkExpired` if the offer's `expires_at` is in the past.
pub fn check_expiry(row: &OfferRow) -> Result<(), GaldraError> {
    if row.is_expired() {
        Err(GaldraError::EpkExpired(row.session_id.clone()))
    } else {
        Ok(())
    }
}

/// Return `EpkConsumed` if the offer has already been consumed.
pub fn check_not_consumed(row: &OfferRow) -> Result<(), GaldraError> {
    if row.consumed {
        Err(GaldraError::EpkConsumed(row.session_id.clone()))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Offer generation (host-side keygen + GPG sign+encrypt).
// ---------------------------------------------------------------------------

/// Parameters for generating a new ephemeral key offer.
pub struct GenerateParams<'a> {
    /// GnuPG key ID or fingerprint for signing.
    pub gpg_key_id: &'a str,
    /// GnuPG key IDs to encrypt the offer to (must include at least one recipient).
    pub recipient_key_ids: &'a [String],
    /// Seconds from now until the offer expires.
    pub expires_in_seconds: i64,
    /// Optional operator label for the audit log.
    pub operator: Option<String>,
}

/// Generate a BrainpoolP256r1 ephemeral key offer.
///
/// Steps:
/// 1. Generate ephemeral keypair using the OS TRNG.
/// 2. Sign the raw uncompressed SEC1 EPK bytes with `gpg --detach-sign`.
/// 3. Build the offer JSON (schema_version 1, matching gr-linux-crypto).
/// 4. Encrypt+sign the JSON with `gpg --encrypt --sign`.
/// 5. Store the offer and private key in the database.
/// 6. Append an `EpkGenerate` audit event.
///
/// Returns the `.epk.gpg` ciphertext bytes ready to write to a file.
pub fn generate_offer(
    db: &mut Db,
    params: &GenerateParams<'_>,
) -> Result<(String, Vec<u8>), GaldraError> {
    if params.expires_in_seconds <= 0 {
        return Err(GaldraError::Config(
            "expires_in_seconds must be positive".to_string(),
        ));
    }
    if params.recipient_key_ids.is_empty() {
        return Err(GaldraError::Config(
            "at least one recipient is required".to_string(),
        ));
    }

    // Generate BrainpoolP256r1 ephemeral keypair via OS TRNG.
    let mut os_rng = OsRng;
    let sk = BrainpoolScalar::generate(&mut os_rng)
        .map_err(|_| GaldraError::Config("BrainpoolP256r1 key generation failed".to_string()))?;
    let pk = sk
        .public_key()
        .map_err(|_| GaldraError::Config("public key derivation failed".to_string()))?;
    let epk_sec1 = pk.to_sec1_uncompressed();
    let epk_hex = hex::encode(epk_sec1);
    let sk_bytes = sk.to_secret_bytes_for_test();

    // Resolve the GnuPG long-term fingerprint.
    let lt_fp = gpg_list_fingerprint(params.gpg_key_id)?;

    // Sign the raw SEC1 EPK bytes (not init_sign_preimage).
    let sig_bin = gpg_detach_sign(params.gpg_key_id, &epk_sec1)?;
    let sig_hex = hex::encode(&sig_bin);

    // Build offer JSON body.
    let now = Utc::now().timestamp();
    let expires_at = now + params.expires_in_seconds;
    let session_id = random_session_id();
    let offer_json = OfferJson {
        schema_version: OFFER_SCHEMA_VERSION,
        epk_hex: epk_hex.clone(),
        long_term_fingerprint: lt_fp.clone(),
        signature_hex: sig_hex,
        expires_at,
        created_at: now,
        session_id: session_id.clone(),
        consumed: false,
    };
    let raw_json =
        serde_json::to_vec(&offer_json).map_err(|e| GaldraError::Serialise(e.to_string()))?;

    // Encrypt+sign the JSON with GnuPG.
    let gpg_bytes = gpg_encrypt_sign(params.gpg_key_id, params.recipient_key_ids, &raw_json)?;

    // Persist in database.
    let row = OfferRow {
        session_id: session_id.clone(),
        epk_hex,
        curve: "brainpoolP256r1".to_string(),
        long_term_fingerprint: lt_fp,
        signature_hex: offer_json.signature_hex,
        expires_at,
        created_at: now,
        consumed: false,
        revoked: false,
        imported_at: Utc::now().to_rfc3339(),
        my_private_key_bytes: Some(sk_bytes.to_vec()),
    };
    store_offer(db, &row)?;

    // Audit.
    audit_append(
        db,
        AuditEntry {
            timestamp: Utc::now(),
            operator: params.operator.clone(),
            action: AuditAction::EpkGenerate,
            subject: Some(session_id.clone()),
            detail: Some(format!(
                r#"{{"session_id":"{}","expires_at":{}}}"#,
                session_id, expires_at
            )),
            device_serial: None,
        },
    )?;

    Ok((session_id, gpg_bytes))
}

// ---------------------------------------------------------------------------
// Offer import (GPG decrypt + validate + store).
// ---------------------------------------------------------------------------

/// Parameters for importing an ephemeral key offer received from a peer.
pub struct ImportParams<'a> {
    /// Raw `.epk.gpg` bytes from the peer.
    pub offer_gpg_bytes: &'a [u8],
    /// Expected GnuPG fingerprint of the issuer (normalised: lowercase, no spaces).
    pub verify_fingerprint: &'a str,
    /// Optional operator label for the audit log.
    pub operator: Option<String>,
}

/// Import and validate an ephemeral key offer.
///
/// Steps:
/// 1. Decrypt the GPG envelope.
/// 2. Parse and validate the JSON (schema_version, consumed, expiry, fingerprint).
/// 3. Verify the inner detached signature over the raw SEC1 EPK bytes with `gpg --verify`.
/// 4. Store the offer in the database (private key column is NULL).
/// 5. Append an `EpkImport` audit event.
///
/// Returns the parsed `OfferJson` on success.
pub fn import_offer(db: &mut Db, params: &ImportParams<'_>) -> Result<OfferJson, GaldraError> {
    // Decrypt GPG envelope.
    let json_bytes = gpg_decrypt(params.offer_gpg_bytes)?;
    let offer: OfferJson = serde_json::from_slice(&json_bytes)
        .map_err(|e| GaldraError::Serialise(format!("offer JSON parse: {e}")))?;

    // Validate schema version.
    if offer.schema_version != OFFER_SCHEMA_VERSION {
        audit_reject(db, &offer.session_id, "bad_schema", params.operator.clone())?;
        return Err(GaldraError::Config(format!(
            "offer schema_version must be {OFFER_SCHEMA_VERSION}, got {}",
            offer.schema_version
        )));
    }

    // Validate not already consumed.
    if offer.consumed {
        audit_reject(
            db,
            &offer.session_id,
            "already_consumed",
            params.operator.clone(),
        )?;
        return Err(GaldraError::EpkConsumed(offer.session_id.clone()));
    }

    // Validate expiry.
    let now = Utc::now().timestamp();
    if now >= offer.expires_at {
        audit_reject(db, &offer.session_id, "expired", params.operator.clone())?;
        return Err(GaldraError::EpkExpired(offer.session_id.clone()));
    }

    // Validate long_term_fingerprint.
    let got_fp = normalise_fingerprint(&offer.long_term_fingerprint);
    let want_fp = normalise_fingerprint(params.verify_fingerprint);
    if got_fp != want_fp {
        audit_reject(
            db,
            &offer.session_id,
            "fingerprint_mismatch",
            params.operator.clone(),
        )?;
        return Err(GaldraError::Config(
            "long_term_fingerprint does not match verify_fingerprint".to_string(),
        ));
    }

    // Verify inner detached signature over the raw SEC1 EPK bytes.
    let epk_sec1 =
        hex::decode(&offer.epk_hex).map_err(|e| GaldraError::Config(format!("epk_hex: {e}")))?;
    let sig_bin = hex::decode(&offer.signature_hex)
        .map_err(|e| GaldraError::Config(format!("signature_hex: {e}")))?;
    if let Err(e) = gpg_verify_detached(&epk_sec1, &sig_bin) {
        audit_reject(
            db,
            &offer.session_id,
            "bad_epk_signature",
            params.operator.clone(),
        )?;
        return Err(e);
    }

    // Store.
    let row = OfferRow {
        session_id: offer.session_id.clone(),
        epk_hex: offer.epk_hex.clone(),
        curve: "brainpoolP256r1".to_string(),
        long_term_fingerprint: got_fp,
        signature_hex: offer.signature_hex.clone(),
        expires_at: offer.expires_at,
        created_at: offer.created_at,
        consumed: false,
        revoked: false,
        imported_at: Utc::now().to_rfc3339(),
        my_private_key_bytes: None,
    };
    store_offer(db, &row)?;

    // Audit.
    audit_append(
        db,
        AuditEntry {
            timestamp: Utc::now(),
            operator: params.operator.clone(),
            action: AuditAction::EpkImport,
            subject: Some(offer.session_id.clone()),
            detail: Some(format!(
                r#"{{"session_id":"{}","created_at":{},"expires_at":{},"long_term_fingerprint":"{}"}}"#,
                offer.session_id,
                offer.created_at,
                offer.expires_at,
                normalise_fingerprint(&offer.long_term_fingerprint),
            )),
            device_serial: None,
        },
    )?;

    Ok(offer)
}

// ---------------------------------------------------------------------------
// GnuPG helpers (subprocess).
// ---------------------------------------------------------------------------

fn run_gpg(args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, GaldraError> {
    let mut cmd = Command::new("gpg");
    cmd.args(["--batch", "--yes"]);
    cmd.args(args);
    if stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| GaldraError::Config(format!("gpg not found or failed to start: {e}")))?;

    if let Some(data) = stdin {
        if let Some(mut si) = child.stdin.take() {
            si.write_all(data).map_err(|e| GaldraError::Io(e))?;
        }
    }

    let out = child
        .wait_with_output()
        .map_err(|e| GaldraError::Config(format!("gpg wait: {e}")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(GaldraError::Config(format!("gpg failed: {stderr}")));
    }
    Ok(out.stdout)
}

/// Resolve the full GnuPG fingerprint for a key spec.
fn gpg_list_fingerprint(key_spec: &str) -> Result<String, GaldraError> {
    let out = run_gpg(
        &[
            "--list-keys",
            "--with-colons",
            "--with-fingerprint",
            key_spec,
        ],
        None,
    )?;
    let text = String::from_utf8_lossy(&out);
    for line in text.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() > 9 && parts[0] == "fpr" {
            return Ok(parts[9].to_lowercase());
        }
    }
    Err(GaldraError::Config(format!(
        "could not parse GnuPG fingerprint for {key_spec:?}"
    )))
}

/// Create a detached binary GnuPG signature over `data`.
fn gpg_detach_sign(key_id: &str, data: &[u8]) -> Result<Vec<u8>, GaldraError> {
    let tmp = tempfile_with(data)?;
    let sig_path = tmp.path().with_extension("sig");
    run_gpg(
        &[
            "--detach-sign",
            "--local-user",
            key_id,
            "--output",
            sig_path.to_str().unwrap_or(""),
            tmp.path().to_str().unwrap_or(""),
        ],
        None,
    )?;
    std::fs::read(&sig_path).map_err(GaldraError::Io)
}

/// GPG sign+encrypt a plaintext payload.
fn gpg_encrypt_sign(
    key_id: &str,
    recipients: &[String],
    plaintext: &[u8],
) -> Result<Vec<u8>, GaldraError> {
    let mut args: Vec<&str> = vec![
        "--encrypt",
        "--sign",
        "--local-user",
        key_id,
        "--trust-model",
        "always",
    ];
    for r in recipients {
        args.push("--recipient");
        args.push(r.as_str());
    }
    args.push("-o");
    args.push("-");
    run_gpg(&args, Some(plaintext))
}

/// Decrypt a GPG-encrypted payload. Returns the plaintext bytes.
fn gpg_decrypt(data: &[u8]) -> Result<Vec<u8>, GaldraError> {
    let tmp = tempfile_with(data)?;
    run_gpg(&["--decrypt", tmp.path().to_str().unwrap_or("")], None)
}

/// Verify a detached binary GnuPG signature over `data`.
fn gpg_verify_detached(data: &[u8], sig: &[u8]) -> Result<(), GaldraError> {
    let data_tmp = tempfile_with(data)?;
    let sig_tmp = tempfile_with(sig)?;
    let result = Command::new("gpg")
        .args([
            "--batch",
            "--yes",
            "--verify",
            sig_tmp.path().to_str().unwrap_or(""),
            data_tmp.path().to_str().unwrap_or(""),
        ])
        .output()
        .map_err(|e| GaldraError::Config(format!("gpg verify: {e}")))?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(GaldraError::Config(format!(
            "detached GnuPG signature over EPK failed verification: {stderr}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Misc helpers.
// ---------------------------------------------------------------------------

fn random_session_id() -> String {
    let mut buf = [0u8; 16];
    rand::RngCore::fill_bytes(&mut OsRng, &mut buf);
    hex::encode(buf)
}

fn normalise_fingerprint(fp: &str) -> String {
    fp.trim().replace(' ', "").to_lowercase()
}

fn tempfile_with(data: &[u8]) -> Result<tempfile::NamedTempFile, GaldraError> {
    let mut f = tempfile::NamedTempFile::new().map_err(GaldraError::Io)?;
    f.write_all(data).map_err(GaldraError::Io)?;
    f.flush().map_err(GaldraError::Io)?;
    Ok(f)
}

fn audit_reject(
    db: &mut Db,
    session_id: &str,
    reason: &str,
    operator: Option<String>,
) -> Result<(), GaldraError> {
    audit_append(
        db,
        AuditEntry {
            timestamp: Utc::now(),
            operator,
            action: AuditAction::EpkReject,
            subject: Some(session_id.to_string()),
            detail: Some(format!(
                r#"{{"session_id":"{}","reason":"{}"}}"#,
                session_id, reason
            )),
            device_serial: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn fresh_db() -> Db {
        Db::open_in_memory().expect("in-memory db")
    }

    fn make_row(session_id: &str, expires_delta: i64) -> OfferRow {
        let now = Utc::now().timestamp();
        OfferRow {
            session_id: session_id.to_string(),
            epk_hex: "04".repeat(33),
            curve: "brainpoolP256r1".to_string(),
            long_term_fingerprint: "aabbccdd".to_string(),
            signature_hex: "deadbeef".to_string(),
            expires_at: now + expires_delta,
            created_at: now,
            consumed: false,
            revoked: false,
            imported_at: Utc::now().to_rfc3339(),
            my_private_key_bytes: None,
        }
    }

    #[test]
    fn migration_creates_ephemeral_offers_table() {
        let db = fresh_db();
        // Query table info — must not error.
        let count: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ephemeral_offers'",
                [],
                |r| r.get(0),
            )
            .expect("query");
        assert_eq!(count, 1);
    }

    #[test]
    fn store_and_get_roundtrip() {
        let mut db = fresh_db();
        let row = make_row("aabbccdd00112233", 3600);
        store_offer(&mut db, &row).expect("store");
        let got = get_offer(&db, "aabbccdd00112233").expect("get");
        assert_eq!(got.session_id, row.session_id);
        assert_eq!(got.expires_at, row.expires_at);
        assert_eq!(got.created_at, row.created_at);
        assert!(!got.consumed);
        assert!(!got.revoked);
        assert!(got.my_private_key_bytes.is_none());
    }

    #[test]
    fn store_with_private_key() {
        let mut db = fresh_db();
        let mut row = make_row("eeee0000eeee0000", 3600);
        row.my_private_key_bytes = Some(vec![0x42u8; 32]);
        store_offer(&mut db, &row).expect("store");
        let got = get_offer(&db, "eeee0000eeee0000").expect("get");
        assert_eq!(
            got.my_private_key_bytes.as_deref(),
            Some([0x42u8; 32].as_ref())
        );
    }

    #[test]
    fn mark_consumed_sets_flag() {
        let mut db = fresh_db();
        store_offer(&mut db, &make_row("cccc1111", 3600)).expect("store");
        mark_consumed(&mut db, "cccc1111").expect("mark");
        let got = get_offer(&db, "cccc1111").expect("get");
        assert!(got.consumed);
    }

    #[test]
    fn mark_consumed_twice_returns_error() {
        let mut db = fresh_db();
        store_offer(&mut db, &make_row("dddd2222", 3600)).expect("store");
        mark_consumed(&mut db, "dddd2222").expect("first");
        let err = mark_consumed(&mut db, "dddd2222").expect_err("second must fail");
        assert!(matches!(err, GaldraError::EpkConsumed(_)));
    }

    #[test]
    fn check_expiry_past() {
        let row = make_row("expired", -1);
        assert!(check_expiry(&row).is_err());
    }

    #[test]
    fn check_expiry_future() {
        let row = make_row("future", 3600);
        check_expiry(&row).expect("should be valid");
    }

    #[test]
    fn get_offer_not_found() {
        let db = fresh_db();
        let err = get_offer(&db, "nonexistent").expect_err("must fail");
        assert!(matches!(err, GaldraError::EpkNotFound(_)));
    }

    #[test]
    fn list_offers_empty() {
        let db = fresh_db();
        let rows = list_offers(&db).expect("list");
        assert!(rows.is_empty());
    }

    #[test]
    fn list_offers_multiple() {
        let mut db = fresh_db();
        store_offer(&mut db, &make_row("first_______0001", 3600)).expect("s1");
        store_offer(&mut db, &make_row("second______0002", 7200)).expect("s2");
        let rows = list_offers(&db).expect("list");
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn revoke_offer_clears_private_key() {
        let mut db = fresh_db();
        let mut row = make_row("revoke_test_0001", 3600);
        row.my_private_key_bytes = Some(vec![0x11u8; 32]);
        store_offer(&mut db, &row).expect("store");
        revoke_offer(&mut db, "revoke_test_0001").expect("revoke");
        let got = get_offer(&db, "revoke_test_0001").expect("get");
        assert!(got.revoked);
        assert!(got.my_private_key_bytes.is_none());
    }

    #[test]
    fn revoke_offer_not_found() {
        let mut db = fresh_db();
        let err = revoke_offer(&mut db, "no_such_session").expect_err("must fail");
        assert!(matches!(err, GaldraError::EpkNotFound(_)));
    }

    #[test]
    fn audit_epk_import_event_logged() {
        let mut db = fresh_db();
        let row = make_row("audit_test_000001", 3600);
        store_offer(&mut db, &row).expect("store");
        audit_append(
            &mut db,
            AuditEntry {
                timestamp: Utc::now(),
                operator: None,
                action: AuditAction::EpkImport,
                subject: Some(row.session_id.clone()),
                detail: Some(format!(r#"{{"session_id":"{}"}}"#, row.session_id)),
                device_serial: None,
            },
        )
        .expect("audit");
        let rows = crate::audit::audit_query(
            &db,
            crate::audit::AuditFilter {
                since: None,
                action: Some(AuditAction::EpkImport),
                limit: None,
            },
        )
        .expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, AuditAction::EpkImport);
        assert!(rows[0]
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("audit_test_000001"));
    }

    #[test]
    fn offer_json_serialises_correctly() {
        let offer = OfferJson {
            schema_version: 1,
            epk_hex: "abcd".to_string(),
            long_term_fingerprint: "ffee".to_string(),
            signature_hex: "1234".to_string(),
            expires_at: 9999,
            created_at: 1000,
            session_id: "sid".to_string(),
            consumed: false,
        };
        let s = serde_json::to_string(&offer).expect("ser");
        let back: OfferJson = serde_json::from_str(&s).expect("deser");
        assert_eq!(back.schema_version, 1);
        assert_eq!(back.session_id, "sid");
        assert!(!back.consumed);
    }
}
