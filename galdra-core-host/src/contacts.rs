//! Contact (identity) CRUD and public key updates.

use crate::db::Db;
use crate::GaldraError;
use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Source of a stored public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeySource {
    /// Retrieved from an HKP keyserver.
    Keyserver,
    /// Web Key Directory.
    Wkd,
    /// LDAP / Active Directory.
    Ldap,
    /// Manually entered.
    Manual,
    /// Imported from a file.
    File,
    /// Received from a peer token.
    Peer,
}

impl KeySource {
    /// Serialise to the database representation.
    pub fn as_str(self) -> &'static str {
        match self {
            KeySource::Keyserver => "keyserver",
            KeySource::Wkd => "wkd",
            KeySource::Ldap => "ldap",
            KeySource::Manual => "manual",
            KeySource::File => "file",
            KeySource::Peer => "peer",
        }
    }

    pub(crate) fn from_str(s: &str) -> Option<KeySource> {
        match s {
            "keyserver" => Some(KeySource::Keyserver),
            "wkd" => Some(KeySource::Wkd),
            "ldap" => Some(KeySource::Ldap),
            "manual" => Some(KeySource::Manual),
            "file" => Some(KeySource::File),
            "peer" => Some(KeySource::Peer),
            _ => None,
        }
    }
}

/// Stored contact identity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Identity {
    /// Stable primary key.
    pub id: String,
    /// Primary display name.
    pub display_name: String,
    /// Amateur radio callsign, if any.
    pub callsign: Option<String>,
    /// Primary email address.
    pub email: Option<String>,
    /// Badge or employee ID.
    pub badge_number: Option<String>,
    /// Organisation or agency.
    pub organisation: Option<String>,
    /// Department or team.
    pub department: Option<String>,
    /// Functional role label.
    pub role: Option<String>,
    /// Free-form notes (also searchable).
    pub note: Option<String>,
    /// OpenPGP fingerprint (hex).
    pub pgp_fingerprint: Option<String>,
    /// Raw OpenPGP public key packet bytes.
    pub pgp_pubkey: Option<Vec<u8>>,
    /// When the key was last fetched.
    pub fetched_at: Option<DateTime<Utc>>,
    /// When the key expires, if known.
    pub expires_at: Option<DateTime<Utc>>,
    /// Provenance of the key material.
    pub source: KeySource,
}

/// Fields required to create a new contact without a key.
#[derive(Debug, Clone)]
pub struct NewContact {
    /// Display name (required).
    pub display_name: String,
    /// Optional callsign.
    pub callsign: Option<String>,
    /// Optional email.
    pub email: Option<String>,
    /// Optional badge number.
    pub badge_number: Option<String>,
    /// Optional organisation.
    pub organisation: Option<String>,
    /// Optional department.
    pub department: Option<String>,
    /// Optional role.
    pub role: Option<String>,
    /// Optional note.
    pub note: Option<String>,
}

/// Partial update for an existing contact.
#[derive(Debug, Clone, Default)]
pub struct ContactUpdate {
    /// New display name, if any.
    pub display_name: Option<String>,
    /// New callsign.
    pub callsign: Option<String>,
    /// New email.
    pub email: Option<String>,
    /// New badge number.
    pub badge_number: Option<String>,
    /// New organisation.
    pub organisation: Option<String>,
    /// New department.
    pub department: Option<String>,
    /// New role.
    pub role: Option<String>,
    /// New note.
    pub note: Option<String>,
}

/// Filters for listing contacts.
#[derive(Debug, Clone, Default)]
pub struct ContactFilter {
    /// When true, only identities with expired keys are listed.
    pub expired: bool,
    /// Filter by organisation substring.
    pub organisation: Option<String>,
    /// Filter by role substring.
    pub role: Option<String>,
}

/// Map identity columns starting at `start` (14 consecutive columns).
pub(crate) fn identity_from_row_offset(
    row: &rusqlite::Row<'_>,
    start: usize,
) -> Result<Identity, rusqlite::Error> {
    let source_str: String = row.get(start + 13)?;
    let source = KeySource::from_str(&source_str).unwrap_or(KeySource::Manual);
    let fetched_at_s: Option<String> = row.get(start + 11)?;
    let expires_at_s: Option<String> = row.get(start + 12)?;
    let fetched_at = match &fetched_at_s {
        None => None,
        Some(s) => DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|d| d.with_timezone(&Utc)),
    };
    let expires_at = match &expires_at_s {
        None => None,
        Some(s) => DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|d| d.with_timezone(&Utc)),
    };
    Ok(Identity {
        id: row.get(start)?,
        display_name: row.get(start + 1)?,
        callsign: row.get(start + 2)?,
        email: row.get(start + 3)?,
        badge_number: row.get(start + 4)?,
        organisation: row.get(start + 5)?,
        department: row.get(start + 6)?,
        role: row.get(start + 7)?,
        note: row.get(start + 8)?,
        pgp_fingerprint: row.get(start + 9)?,
        pgp_pubkey: row.get(start + 10)?,
        fetched_at,
        expires_at,
        source,
    })
}

fn row_to_identity(row: &rusqlite::Row<'_>) -> Result<Identity, rusqlite::Error> {
    identity_from_row_offset(row, 0)
}

/// Insert a new contact row without a public key.
pub fn contact_add(db: &mut Db, contact: NewContact) -> Result<Identity, GaldraError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    db.connection_mut()
        .execute(
            r"INSERT INTO identities (
            id, display_name, callsign, email, badge_number, organisation, department,
            role, note, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL, ?10, NULL, 'manual')",
            params![
                id,
                contact.display_name,
                contact.callsign,
                contact.email,
                contact.badge_number,
                contact.organisation,
                contact.department,
                contact.role,
                contact.note,
                now,
            ],
        )
        .map_err(GaldraError::Database)?;
    contact_get_by_id(db, &id)
}

/// Load a contact by primary key.
pub fn contact_get_by_id(db: &Db, id: &str) -> Result<Identity, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT id, display_name, callsign, email, badge_number, organisation, department,
            role, note, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities WHERE id = ?1",
        )
        .map_err(GaldraError::Database)?;
    stmt
        .query_row([id], row_to_identity)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                GaldraError::ContactNotFound(id.to_string())
            }
            e => GaldraError::Database(e),
        })
}

/// Load a contact by amateur radio callsign.
pub fn contact_get_by_callsign(db: &Db, callsign: &str) -> Result<Identity, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT id, display_name, callsign, email, badge_number, organisation, department,
            role, note, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities WHERE callsign = ?1",
        )
        .map_err(GaldraError::Database)?;
    stmt
        .query_row([callsign], row_to_identity)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                GaldraError::ContactNotFound(callsign.to_string())
            }
            e => GaldraError::Database(e),
        })
}

/// Load a contact by primary email address.
pub fn contact_get_by_email(db: &Db, email: &str) -> Result<Identity, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT id, display_name, callsign, email, badge_number, organisation, department,
            role, note, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities WHERE email = ?1",
        )
        .map_err(GaldraError::Database)?;
    stmt
        .query_row([email], row_to_identity)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                GaldraError::ContactNotFound(email.to_string())
            }
            e => GaldraError::Database(e),
        })
}

/// Search contacts across textual fields using SQL `LIKE`.
pub fn contact_search(db: &Db, query: &str) -> Result<Vec<Identity>, GaldraError> {
    let pattern = format!("%{}%", query.replace('%', "\\%").replace('_', "\\_"));
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT id, display_name, callsign, email, badge_number, organisation, department,
            role, note, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities
            WHERE display_name LIKE ?1 ESCAPE '\'
               OR IFNULL(callsign, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(email, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(badge_number, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(role, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(note, '') LIKE ?1 ESCAPE '\'
            ORDER BY display_name COLLATE NOCASE",
        )
        .map_err(GaldraError::Database)?;
    let rows = stmt
        .query_map([&pattern], row_to_identity)
        .map_err(GaldraError::Database)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(GaldraError::Database)?);
    }
    Ok(out)
}

/// Apply a partial update to an existing contact (metadata only unless upsert key).
pub fn contact_update(db: &mut Db, id: &str, update: ContactUpdate) -> Result<Identity, GaldraError> {
    let _ = contact_get_by_id(db, id)?;
    if update.display_name.is_none()
        && update.callsign.is_none()
        && update.email.is_none()
        && update.badge_number.is_none()
        && update.organisation.is_none()
        && update.department.is_none()
        && update.role.is_none()
        && update.note.is_none()
    {
        return contact_get_by_id(db, id);
    }
    db.connection_mut()
        .execute(
            r"UPDATE identities SET
                display_name = COALESCE(?2, display_name),
                callsign = COALESCE(?3, callsign),
                email = COALESCE(?4, email),
                badge_number = COALESCE(?5, badge_number),
                organisation = COALESCE(?6, organisation),
                department = COALESCE(?7, department),
                role = COALESCE(?8, role),
                note = COALESCE(?9, note)
            WHERE id = ?1",
            params![
                id,
                update.display_name,
                update.callsign,
                update.email,
                update.badge_number,
                update.organisation,
                update.department,
                update.role,
                update.note,
            ],
        )
        .map_err(GaldraError::Database)?;
    contact_get_by_id(db, id)
}

/// Delete a contact and cascade group membership.
pub fn contact_delete(db: &mut Db, id: &str) -> Result<(), GaldraError> {
    let n = db
        .connection_mut()
        .execute("DELETE FROM identities WHERE id = ?1", [id])
        .map_err(GaldraError::Database)?;
    if n == 0 {
        return Err(GaldraError::ContactNotFound(id.to_string()));
    }
    Ok(())
}

/// List contacts with optional filters.
pub fn contact_list(db: &Db, filter: ContactFilter) -> Result<Vec<Identity>, GaldraError> {
    let now = Utc::now().to_rfc3339();
    let mut sql = String::from(
        r"SELECT id, display_name, callsign, email, badge_number, organisation, department,
        role, note, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
        FROM identities WHERE 1=1",
    );
    if filter.expired {
        sql.push_str(" AND expires_at IS NOT NULL AND expires_at < ?");
    }
    if filter.organisation.is_some() {
        sql.push_str(" AND IFNULL(organisation, '') LIKE ? ESCAPE '\\'");
    }
    if filter.role.is_some() {
        sql.push_str(" AND IFNULL(role, '') LIKE ? ESCAPE '\\'");
    }
    sql.push_str(" ORDER BY display_name COLLATE NOCASE");

    let mut stmt = db.connection().prepare(&sql).map_err(GaldraError::Database)?;
    let mut params: Vec<String> = Vec::new();
    if filter.expired {
        params.push(now);
    }
    if let Some(o) = &filter.organisation {
        params.push(format!("%{}%", o));
    }
    if let Some(r) = &filter.role {
        params.push(format!("%{}%", r));
    }

    let rows = if params.is_empty() {
        stmt.query_map([], row_to_identity)
    } else {
        stmt.query_map(rusqlite::params_from_iter(params.iter()), row_to_identity)
    }
    .map_err(GaldraError::Database)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(GaldraError::Database)?);
    }
    Ok(out)
}

/// Update or insert public key material for a contact.
pub fn contact_upsert_key(
    db: &mut Db,
    id: &str,
    pubkey: &[u8],
    fingerprint: &str,
    source: KeySource,
    expires_at: Option<DateTime<Utc>>,
) -> Result<(), GaldraError> {
    let _ = contact_get_by_id(db, id)?;
    let fetched_at = Utc::now().to_rfc3339();
    let exp = expires_at.map(|t| t.to_rfc3339());
    db.connection_mut()
        .execute(
            r"UPDATE identities SET
                pgp_pubkey = ?2,
                pgp_fingerprint = ?3,
                source = ?4,
                fetched_at = ?5,
                expires_at = ?6
            WHERE id = ?1",
            params![
                id,
                pubkey,
                fingerprint,
                source.as_str(),
                fetched_at,
                exp,
            ],
        )
        .map_err(GaldraError::Database)?;
    Ok(())
}
