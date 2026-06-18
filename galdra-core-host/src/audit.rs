//! Append-only audit log with SHA-256 hash chain integrity.

use crate::db::Db;
use crate::GaldraError;
use chrono::{DateTime, Utc};
use rusqlite::params;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;

/// Actions recorded in the audit log (matches the specification table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Token unlocked with PIN.
    DeviceUnlock,
    /// Token locked.
    DeviceLock,
    /// Token zeroised.
    DeviceZeroise,
    /// Public key imported.
    KeyImport,
    /// Contact or key removed.
    KeyDelete,
    /// Key fetched from a remote source.
    KeyFetch,
    /// Group created.
    GroupCreate,
    /// Member added to a group.
    GroupAddMember,
    /// Member removed from a group.
    GroupRemoveMember,
    /// Group deleted.
    GroupDelete,
    /// Ciphertext produced.
    Encrypt,
    /// Plaintext recovered.
    Decrypt,
    /// Data signed.
    Sign,
    /// Signature checked.
    Verify,
    /// Sync package exported.
    SyncExport,
    /// Sync package imported.
    SyncImport,
    /// Configuration changed.
    ConfigChange,
    /// Ephemeral key offer generated.
    EpkGenerate,
    /// Ephemeral key offer imported from a peer.
    EpkImport,
    /// Session keys derived from an ephemeral offer.
    EpkDerive,
    /// Ephemeral key offer rejected (bad schema, expired, consumed, fingerprint mismatch, etc.).
    EpkReject,
}

impl AuditAction {
    /// Wire-format action name stored in SQLite and exports.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::DeviceUnlock => "device_unlock",
            AuditAction::DeviceLock => "device_lock",
            AuditAction::DeviceZeroise => "device_zeroise",
            AuditAction::KeyImport => "key_import",
            AuditAction::KeyDelete => "key_delete",
            AuditAction::KeyFetch => "key_fetch",
            AuditAction::GroupCreate => "group_create",
            AuditAction::GroupAddMember => "group_add_member",
            AuditAction::GroupRemoveMember => "group_remove_member",
            AuditAction::GroupDelete => "group_delete",
            AuditAction::Encrypt => "encrypt",
            AuditAction::Decrypt => "decrypt",
            AuditAction::Sign => "sign",
            AuditAction::Verify => "verify",
            AuditAction::SyncExport => "sync_export",
            AuditAction::SyncImport => "sync_import",
            AuditAction::ConfigChange => "config_change",
            AuditAction::EpkGenerate => "epk_generate",
            AuditAction::EpkImport => "epk_import",
            AuditAction::EpkDerive => "epk_derive",
            AuditAction::EpkReject => "epk_reject",
        }
    }

    /// Parse the wire-format action name stored in SQLite and exports.
    pub fn from_wire(s: &str) -> Option<AuditAction> {
        match s {
            "device_unlock" => Some(AuditAction::DeviceUnlock),
            "device_lock" => Some(AuditAction::DeviceLock),
            "device_zeroise" => Some(AuditAction::DeviceZeroise),
            "key_import" => Some(AuditAction::KeyImport),
            "key_delete" => Some(AuditAction::KeyDelete),
            "key_fetch" => Some(AuditAction::KeyFetch),
            "group_create" => Some(AuditAction::GroupCreate),
            "group_add_member" => Some(AuditAction::GroupAddMember),
            "group_remove_member" => Some(AuditAction::GroupRemoveMember),
            "group_delete" => Some(AuditAction::GroupDelete),
            "encrypt" => Some(AuditAction::Encrypt),
            "decrypt" => Some(AuditAction::Decrypt),
            "sign" => Some(AuditAction::Sign),
            "verify" => Some(AuditAction::Verify),
            "sync_export" => Some(AuditAction::SyncExport),
            "sync_import" => Some(AuditAction::SyncImport),
            "config_change" => Some(AuditAction::ConfigChange),
            "epk_generate" => Some(AuditAction::EpkGenerate),
            "epk_import" => Some(AuditAction::EpkImport),
            "epk_derive" => Some(AuditAction::EpkDerive),
            "epk_reject" => Some(AuditAction::EpkReject),
            _ => None,
        }
    }
}

/// Input for a new audit row (hash chain computed automatically).
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Event time (UTC).
    pub timestamp: DateTime<Utc>,
    /// Acting operator label, if any.
    pub operator: Option<String>,
    /// High-level action category.
    pub action: AuditAction,
    /// Primary subject identifier (contact id, group name, etc.).
    pub subject: Option<String>,
    /// Human-readable detail (no secrets).
    pub detail: Option<String>,
    /// Device serial when relevant.
    pub device_serial: Option<String>,
}

/// Stored audit row including chain metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Database primary key.
    pub id: i64,
    /// Hex-encoded SHA-256 of the previous entry payload (genesis is all-zero bytes).
    pub prev_hash: String,
    /// Event time.
    pub timestamp: DateTime<Utc>,
    /// Operator label.
    pub operator: Option<String>,
    /// Action.
    pub action: AuditAction,
    /// Subject.
    pub subject: Option<String>,
    /// Detail.
    pub detail: Option<String>,
    /// Device serial.
    pub device_serial: Option<String>,
}

/// Filters for querying or exporting audit rows.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Only rows at or after this instant.
    pub since: Option<DateTime<Utc>>,
    /// Optional action filter.
    pub action: Option<AuditAction>,
    /// Maximum rows to return (None = unlimited).
    pub limit: Option<u64>,
}

/// Result of verifying the audit hash chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum AuditVerifyResult {
    /// Chain is intact.
    Ok,
    /// Tampering detected at `entry_id`.
    ChainBroken {
        /// Row id where the mismatch occurs.
        entry_id: i64,
        /// Expected `prev_hash` for this row.
        expected_hash: String,
        /// Stored `prev_hash` for this row.
        actual_hash: String,
    },
}

#[derive(Serialize)]
struct ChainPayload {
    timestamp: String,
    operator: Option<String>,
    action: String,
    subject: Option<String>,
    detail: Option<String>,
    device_serial: Option<String>,
}

type LastAuditFields = (
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn genesis_prev_hash() -> String {
    "0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

fn hash_payload(payload: &ChainPayload) -> Result<String, GaldraError> {
    let json = serde_json::to_string(payload).map_err(|e| GaldraError::Serialise(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let out = hasher.finalize();
    Ok(hex::encode(out))
}

fn record_to_payload(
    timestamp: &str,
    operator: &Option<String>,
    action: &str,
    subject: &Option<String>,
    detail: &Option<String>,
    device_serial: &Option<String>,
) -> Result<ChainPayload, GaldraError> {
    Ok(ChainPayload {
        timestamp: timestamp.to_string(),
        operator: operator.clone(),
        action: action.to_string(),
        subject: subject.clone(),
        detail: detail.clone(),
        device_serial: device_serial.clone(),
    })
}

/// Append a single audit row (only supported writer for `audit_log`).
pub fn audit_append(db: &mut Db, entry: AuditEntry) -> Result<(), GaldraError> {
    let prev_hash = match last_audit_row(db)? {
        None => genesis_prev_hash(),
        Some((ts, op, act, sub, det, dev)) => {
            let prev = record_to_payload(&ts, &op, &act, &sub, &det, &dev)?;
            hash_payload(&prev)?
        }
    };

    db.connection_mut()
        .execute(
            r"INSERT INTO audit_log (timestamp, operator, action, subject, detail, device_serial, prev_hash)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.timestamp.to_rfc3339(),
                entry.operator,
                entry.action.as_str(),
                entry.subject,
                entry.detail,
                entry.device_serial,
                prev_hash,
            ],
        )
        .map_err(GaldraError::Database)?;
    Ok(())
}

fn last_audit_row(db: &Db) -> Result<Option<LastAuditFields>, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT timestamp, operator, action, subject, detail, device_serial
            FROM audit_log ORDER BY id DESC LIMIT 1",
        )
        .map_err(GaldraError::Database)?;
    let row = stmt
        .query_row([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get(1)?,
                row.get::<_, String>(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .optional()
        .map_err(GaldraError::Database)?;
    Ok(row)
}

/// Query audit rows with optional filters.
pub fn audit_query(db: &Db, filter: AuditFilter) -> Result<Vec<AuditRecord>, GaldraError> {
    let mut sql = String::from(
        r"SELECT id, prev_hash, timestamp, operator, action, subject, detail, device_serial
        FROM audit_log WHERE 1=1",
    );
    if filter.since.is_some() {
        sql.push_str(" AND timestamp >= ?");
    }
    if filter.action.is_some() {
        sql.push_str(" AND action = ?");
    }
    sql.push_str(" ORDER BY id ASC");
    if filter.limit.is_some() {
        sql.push_str(" LIMIT ?");
    }

    let mut stmt = db
        .connection()
        .prepare(&sql)
        .map_err(GaldraError::Database)?;
    let mut bind: Vec<String> = Vec::new();
    if let Some(s) = filter.since {
        bind.push(s.to_rfc3339());
    }
    if let Some(a) = filter.action {
        bind.push(a.as_str().to_string());
    }
    if let Some(l) = filter.limit {
        bind.push(l.to_string());
    }

    let rows = if bind.is_empty() {
        stmt.query_map([], map_audit_row)
    } else {
        stmt.query_map(rusqlite::params_from_iter(bind.iter()), map_audit_row)
    }
    .map_err(GaldraError::Database)?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(GaldraError::Database)?);
    }
    Ok(out)
}

fn map_audit_row(row: &rusqlite::Row<'_>) -> Result<AuditRecord, rusqlite::Error> {
    let id: i64 = row.get(0)?;
    let prev_hash: String = row.get(1)?;
    let ts: String = row.get(2)?;
    let operator: Option<String> = row.get(3)?;
    let action_s: String = row.get(4)?;
    let subject: Option<String> = row.get(5)?;
    let detail: Option<String> = row.get(6)?;
    let device_serial: Option<String> = row.get(7)?;
    let action = AuditAction::from_wire(&action_s).unwrap_or(AuditAction::ConfigChange);
    let timestamp = DateTime::parse_from_rfc3339(&ts)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    Ok(AuditRecord {
        id,
        prev_hash,
        timestamp,
        operator,
        action,
        subject,
        detail,
        device_serial,
    })
}

/// Verify the audit hash chain end-to-end.
pub fn audit_verify_chain(db: &Db) -> Result<AuditVerifyResult, GaldraError> {
    let rows = audit_query(
        db,
        AuditFilter {
            since: None,
            action: None,
            limit: None,
        },
    )?;

    if rows.is_empty() {
        return Ok(AuditVerifyResult::Ok);
    }

    let genesis = genesis_prev_hash();
    for (idx, rec) in rows.iter().enumerate() {
        if idx == 0 {
            if rec.prev_hash != genesis {
                return Ok(AuditVerifyResult::ChainBroken {
                    entry_id: rec.id,
                    expected_hash: genesis.clone(),
                    actual_hash: rec.prev_hash.clone(),
                });
            }
            continue;
        }
        let prev = &rows[idx - 1];
        let payload = record_to_payload(
            &prev.timestamp.to_rfc3339(),
            &prev.operator,
            prev.action.as_str(),
            &prev.subject,
            &prev.detail,
            &prev.device_serial,
        )?;
        let expected = hash_payload(&payload)?;
        if rec.prev_hash != expected {
            return Ok(AuditVerifyResult::ChainBroken {
                entry_id: rec.id,
                expected_hash: expected,
                actual_hash: rec.prev_hash.clone(),
            });
        }
    }

    Ok(AuditVerifyResult::Ok)
}

/// Export matching rows as CSV.
pub fn audit_export_csv(
    db: &Db,
    filter: AuditFilter,
    writer: &mut impl std::io::Write,
) -> Result<(), GaldraError> {
    let rows = audit_query(db, filter)?;
    writeln!(
        writer,
        "id,prev_hash,timestamp,operator,action,subject,detail,device_serial"
    )
    .map_err(GaldraError::Io)?;
    for r in rows {
        writeln!(
            writer,
            "{},{},{},{},{},{},{},{}",
            r.id,
            r.prev_hash,
            r.timestamp.to_rfc3339(),
            csv_escape(r.operator.as_deref()),
            r.action.as_str(),
            csv_escape(r.subject.as_deref()),
            csv_escape(r.detail.as_deref()),
            csv_escape(r.device_serial.as_deref()),
        )
        .map_err(GaldraError::Io)?;
    }
    Ok(())
}

fn csv_escape(s: Option<&str>) -> String {
    match s {
        None => String::new(),
        Some(t) => {
            if t.contains(',') || t.contains('"') || t.contains('\n') {
                format!("\"{}\"", t.replace('"', "\"\""))
            } else {
                t.to_string()
            }
        }
    }
}

/// Export matching rows as JSON array.
pub fn audit_export_json(
    db: &Db,
    filter: AuditFilter,
    writer: &mut impl std::io::Write,
) -> Result<(), GaldraError> {
    let rows = audit_query(db, filter)?;
    let json =
        serde_json::to_string_pretty(&rows).map_err(|e| GaldraError::Serialise(e.to_string()))?;
    writer.write_all(json.as_bytes()).map_err(GaldraError::Io)?;
    Ok(())
}

// Serialize AuditRecord for JSON export
impl Serialize for AuditRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("AuditRecord", 8)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("prev_hash", &self.prev_hash)?;
        s.serialize_field("timestamp", &self.timestamp.to_rfc3339())?;
        s.serialize_field("operator", &self.operator)?;
        s.serialize_field("action", &self.action.as_str())?;
        s.serialize_field("subject", &self.subject)?;
        s.serialize_field("detail", &self.detail)?;
        s.serialize_field("device_serial", &self.device_serial)?;
        s.end()
    }
}
