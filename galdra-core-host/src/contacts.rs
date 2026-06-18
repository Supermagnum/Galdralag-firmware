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
    /// DMR subscriber ID when known (`None` omits storage).
    pub dmr_id: Option<i64>,
    /// Amateur-radio affiliation labels (clubs, alliances, nets), free text.
    pub radio_affiliation: Option<String>,
    /// Street address line (optional; not verified).
    pub street: Option<String>,
    /// Country name or ISO code (optional).
    pub country: Option<String>,
    /// Postal or ZIP code (optional).
    pub postal_code: Option<String>,
    /// Region, state, county, or similar (optional).
    pub region: Option<String>,
    /// Fluxer handle or id (optional).
    pub fluxer_id: Option<String>,
    /// Discord user id (optional).
    pub discord_id: Option<String>,
    /// IRC nick or similar (optional).
    pub irc_id: Option<String>,
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

/// Fields required to create a new contact without a key (`email` is required).
#[derive(Debug, Clone)]
pub struct NewContact {
    /// Display name (optional; empty string when omitted).
    pub display_name: String,
    /// Primary e-mail (required).
    pub email: String,
    /// Optional callsign.
    pub callsign: Option<String>,
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
    /// Optional DMR subscriber ID (must be positive when set).
    pub dmr_id: Option<i64>,
    /// Optional radio affiliation text.
    pub radio_affiliation: Option<String>,
    /// Optional street line.
    pub street: Option<String>,
    /// Optional country.
    pub country: Option<String>,
    /// Optional postal code.
    pub postal_code: Option<String>,
    /// Optional region / state / county.
    pub region: Option<String>,
    /// Optional Fluxer id.
    pub fluxer_id: Option<String>,
    /// Optional Discord id.
    pub discord_id: Option<String>,
    /// Optional IRC id.
    pub irc_id: Option<String>,
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
    /// New DMR ID.
    pub dmr_id: Option<i64>,
    /// New radio affiliation.
    pub radio_affiliation: Option<String>,
    /// New street line.
    pub street: Option<String>,
    /// New country.
    pub country: Option<String>,
    /// New postal code.
    pub postal_code: Option<String>,
    /// New region / state / county.
    pub region: Option<String>,
    /// New Fluxer id.
    pub fluxer_id: Option<String>,
    /// New Discord id.
    pub discord_id: Option<String>,
    /// New IRC id.
    pub irc_id: Option<String>,
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

/// Map identity columns starting at `start` (23 consecutive columns, `id` through `source`).
pub(crate) fn identity_from_row_offset(
    row: &rusqlite::Row<'_>,
    start: usize,
) -> Result<Identity, rusqlite::Error> {
    let source_str: String = row.get(start + 22)?;
    let source = KeySource::from_str(&source_str).unwrap_or(KeySource::Manual);
    let fetched_at_s: Option<String> = row.get(start + 20)?;
    let expires_at_s: Option<String> = row.get(start + 21)?;
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
        dmr_id: row.get(start + 9)?,
        radio_affiliation: row.get(start + 10)?,
        street: row.get(start + 11)?,
        country: row.get(start + 12)?,
        postal_code: row.get(start + 13)?,
        region: row.get(start + 14)?,
        fluxer_id: row.get(start + 15)?,
        discord_id: row.get(start + 16)?,
        irc_id: row.get(start + 17)?,
        pgp_fingerprint: row.get(start + 18)?,
        pgp_pubkey: row.get(start + 19)?,
        fetched_at,
        expires_at,
        source,
    })
}

fn validate_address_lens(
    street: Option<&str>,
    country: Option<&str>,
    postal_code: Option<&str>,
    region: Option<&str>,
) -> Result<(), GaldraError> {
    const MAX_STREET: usize = 512;
    const MAX_COUNTRY: usize = 128;
    const MAX_POSTAL: usize = 32;
    const MAX_REGION: usize = 128;
    if let Some(s) = street {
        if s.len() > MAX_STREET {
            return Err(GaldraError::Config(format!(
                "street exceeds {} characters",
                MAX_STREET
            )));
        }
    }
    if let Some(s) = country {
        if s.len() > MAX_COUNTRY {
            return Err(GaldraError::Config(format!(
                "country exceeds {} characters",
                MAX_COUNTRY
            )));
        }
    }
    if let Some(s) = postal_code {
        if s.len() > MAX_POSTAL {
            return Err(GaldraError::Config(format!(
                "postal_code exceeds {} characters",
                MAX_POSTAL
            )));
        }
    }
    if let Some(s) = region {
        if s.len() > MAX_REGION {
            return Err(GaldraError::Config(format!(
                "region exceeds {} characters",
                MAX_REGION
            )));
        }
    }
    Ok(())
}

fn validate_social_ids(
    fluxer_id: Option<&str>,
    discord_id: Option<&str>,
    irc_id: Option<&str>,
) -> Result<(), GaldraError> {
    const MAX_FLUXER: usize = 128;
    const MAX_DISCORD: usize = 32;
    const MAX_IRC: usize = 128;
    if let Some(s) = fluxer_id {
        if s.len() > MAX_FLUXER {
            return Err(GaldraError::Config(format!(
                "fluxer_id exceeds {} characters",
                MAX_FLUXER
            )));
        }
    }
    if let Some(s) = discord_id {
        if s.len() > MAX_DISCORD {
            return Err(GaldraError::Config(format!(
                "discord_id exceeds {} characters",
                MAX_DISCORD
            )));
        }
    }
    if let Some(s) = irc_id {
        if s.len() > MAX_IRC {
            return Err(GaldraError::Config(format!(
                "irc_id exceeds {} characters",
                MAX_IRC
            )));
        }
    }
    Ok(())
}

fn row_to_identity(row: &rusqlite::Row<'_>) -> Result<Identity, rusqlite::Error> {
    identity_from_row_offset(row, 0)
}

fn validate_new_contact(contact: &NewContact) -> Result<(), GaldraError> {
    if contact.email.trim().is_empty() {
        return Err(GaldraError::Config("email is required".to_string()));
    }
    if let Some(d) = contact.dmr_id {
        if d <= 0 || d > 16_777_215 {
            return Err(GaldraError::Config(
                "dmr_id must be blank or between 1 and 16777215 (24-bit)".to_string(),
            ));
        }
    }
    if let Some(ref s) = contact.radio_affiliation {
        if s.len() > 128 {
            return Err(GaldraError::Config(
                "radio_affiliation exceeds 128 characters".to_string(),
            ));
        }
    }
    validate_address_lens(
        contact.street.as_deref(),
        contact.country.as_deref(),
        contact.postal_code.as_deref(),
        contact.region.as_deref(),
    )?;
    validate_social_ids(
        contact.fluxer_id.as_deref(),
        contact.discord_id.as_deref(),
        contact.irc_id.as_deref(),
    )?;
    Ok(())
}

/// Insert a new contact row without a public key.
pub fn contact_add(db: &mut Db, contact: NewContact) -> Result<Identity, GaldraError> {
    validate_new_contact(&contact)?;
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    db.connection_mut()
        .execute(
            r"INSERT INTO identities (
            id, display_name, callsign, email, badge_number, organisation, department,
            role, note, dmr_id, radio_affiliation, street, country, postal_code, region,
            fluxer_id, discord_id, irc_id,
            pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
            NULL, NULL, ?19, NULL, 'manual')",
            params![
                id,
                contact.display_name,
                contact.callsign,
                contact.email.trim(),
                contact.badge_number,
                contact.organisation,
                contact.department,
                contact.role,
                contact.note,
                contact.dmr_id,
                contact.radio_affiliation,
                contact.street,
                contact.country,
                contact.postal_code,
                contact.region,
                contact.fluxer_id,
                contact.discord_id,
                contact.irc_id,
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
            role, note, dmr_id, radio_affiliation, street, country, postal_code, region,
            fluxer_id, discord_id, irc_id, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities WHERE id = ?1",
        )
        .map_err(GaldraError::Database)?;
    stmt.query_row([id], row_to_identity).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => GaldraError::ContactNotFound(id.to_string()),
        e => GaldraError::Database(e),
    })
}

/// Load a contact by amateur radio callsign.
pub fn contact_get_by_callsign(db: &Db, callsign: &str) -> Result<Identity, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT id, display_name, callsign, email, badge_number, organisation, department,
            role, note, dmr_id, radio_affiliation, street, country, postal_code, region,
            fluxer_id, discord_id, irc_id, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities WHERE callsign = ?1",
        )
        .map_err(GaldraError::Database)?;
    stmt.query_row([callsign], row_to_identity)
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
            role, note, dmr_id, radio_affiliation, street, country, postal_code, region,
            fluxer_id, discord_id, irc_id, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities WHERE email = ?1",
        )
        .map_err(GaldraError::Database)?;
    stmt.query_row([email], row_to_identity)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => GaldraError::ContactNotFound(email.to_string()),
            e => GaldraError::Database(e),
        })
}

/// Load a contact by Fluxer id.
pub fn contact_get_by_fluxer_id(db: &Db, fluxer_id: &str) -> Result<Identity, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT id, display_name, callsign, email, badge_number, organisation, department,
            role, note, dmr_id, radio_affiliation, street, country, postal_code, region,
            fluxer_id, discord_id, irc_id, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities WHERE fluxer_id = ?1",
        )
        .map_err(GaldraError::Database)?;
    stmt.query_row([fluxer_id], row_to_identity)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                GaldraError::ContactNotFound(fluxer_id.to_string())
            }
            e => GaldraError::Database(e),
        })
}

/// Load a contact by Discord id.
pub fn contact_get_by_discord_id(db: &Db, discord_id: &str) -> Result<Identity, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT id, display_name, callsign, email, badge_number, organisation, department,
            role, note, dmr_id, radio_affiliation, street, country, postal_code, region,
            fluxer_id, discord_id, irc_id, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities WHERE discord_id = ?1",
        )
        .map_err(GaldraError::Database)?;
    stmt.query_row([discord_id], row_to_identity)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                GaldraError::ContactNotFound(discord_id.to_string())
            }
            e => GaldraError::Database(e),
        })
}

/// Load a contact by IRC id.
pub fn contact_get_by_irc_id(db: &Db, irc_id: &str) -> Result<Identity, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT id, display_name, callsign, email, badge_number, organisation, department,
            role, note, dmr_id, radio_affiliation, street, country, postal_code, region,
            fluxer_id, discord_id, irc_id, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities WHERE irc_id = ?1",
        )
        .map_err(GaldraError::Database)?;
    stmt.query_row([irc_id], row_to_identity)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => GaldraError::ContactNotFound(irc_id.to_string()),
            e => GaldraError::Database(e),
        })
}

/// Normalise raw user input into 40-character uppercase hexadecimal (OpenPGP v4 fingerprint),
/// stripping spaces and separators. Returns [`None`] if the token is not exactly 40 hex digits.
pub fn normalize_openpgp_fingerprint_hex(raw: &str) -> Option<String> {
    let compact: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if compact.len() != 40 {
        return None;
    }
    Some(compact.to_ascii_uppercase())
}

/// Load a contact whose stored fingerprint matches `fp_normalized` after the same normalisation as
/// [`normalize_openpgp_fingerprint_hex`] (spacing and `:` tolerated in the DB column).
pub fn contact_get_by_pgp_fingerprint_normalized(
    db: &Db,
    fp_normalized: &str,
) -> Result<Identity, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT id, display_name, callsign, email, badge_number, organisation, department,
            role, note, dmr_id, radio_affiliation, street, country, postal_code, region,
            fluxer_id, discord_id, irc_id, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities
            WHERE replace(replace(upper(trim(ifnull(pgp_fingerprint,''))), ' ', ''), ':', '') = ?1",
        )
        .map_err(GaldraError::Database)?;
    stmt.query_row([fp_normalized], row_to_identity)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                GaldraError::ContactNotFound(fp_normalized.to_string())
            }
            e => GaldraError::Database(e),
        })
}

/// Load a contact by DMR subscriber id (1..=16777215).
pub fn contact_get_by_dmr_id(db: &Db, dmr_id: i64) -> Result<Identity, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT id, display_name, callsign, email, badge_number, organisation, department,
            role, note, dmr_id, radio_affiliation, street, country, postal_code, region,
            fluxer_id, discord_id, irc_id, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities WHERE dmr_id = ?1",
        )
        .map_err(GaldraError::Database)?;
    stmt.query_row([dmr_id], row_to_identity)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                GaldraError::ContactNotFound(dmr_id.to_string())
            }
            e => GaldraError::Database(e),
        })
}

fn try_parse_dmr_subscriber_id(token: &str) -> Option<i64> {
    let t = token.trim();
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n: i64 = t.parse().ok()?;
    if (1..=16_777_215).contains(&n) {
        Some(n)
    } else {
        None
    }
}

/// Resolve `id` to a contact using the same rules as the `galdra` CLI and `galdrad` HTTP API:
/// row UUID, callsign, e-mail, OpenPGP fingerprint (40 hex characters, spaces ignored),
/// Fluxer id, Discord id, IRC id, then DMR subscriber id when the token is decimal in 1..=16777215.
pub fn resolve_contact_identifier(db: &Db, id: &str) -> Result<Identity, GaldraError> {
    if let Ok(c) = contact_get_by_id(db, id) {
        return Ok(c);
    }
    if let Ok(c) = contact_get_by_callsign(db, id) {
        return Ok(c);
    }
    if let Ok(c) = contact_get_by_email(db, id) {
        return Ok(c);
    }
    if let Some(fp) = normalize_openpgp_fingerprint_hex(id) {
        if let Ok(c) = contact_get_by_pgp_fingerprint_normalized(db, &fp) {
            return Ok(c);
        }
    }
    if let Ok(c) = contact_get_by_fluxer_id(db, id) {
        return Ok(c);
    }
    if let Ok(c) = contact_get_by_discord_id(db, id) {
        return Ok(c);
    }
    if let Ok(c) = contact_get_by_irc_id(db, id) {
        return Ok(c);
    }
    if let Some(dmr) = try_parse_dmr_subscriber_id(id) {
        if let Ok(c) = contact_get_by_dmr_id(db, dmr) {
            return Ok(c);
        }
    }
    Err(GaldraError::ContactNotFound(id.to_string()))
}

/// Search contacts across textual fields using SQL `LIKE`.
pub fn contact_search(db: &Db, query: &str) -> Result<Vec<Identity>, GaldraError> {
    let pattern = format!("%{}%", query.replace('%', "\\%").replace('_', "\\_"));
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT id, display_name, callsign, email, badge_number, organisation, department,
            role, note, dmr_id, radio_affiliation, street, country, postal_code, region,
            fluxer_id, discord_id, irc_id, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
            FROM identities
            WHERE display_name LIKE ?1 ESCAPE '\'
               OR IFNULL(callsign, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(email, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(badge_number, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(role, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(organisation, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(department, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(note, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(radio_affiliation, '') LIKE ?1 ESCAPE '\'
               OR CAST(dmr_id AS TEXT) LIKE ?1 ESCAPE '\'
               OR IFNULL(street, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(country, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(postal_code, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(region, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(fluxer_id, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(discord_id, '') LIKE ?1 ESCAPE '\'
               OR IFNULL(irc_id, '') LIKE ?1 ESCAPE '\'
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

fn validate_contact_update(update: &ContactUpdate) -> Result<(), GaldraError> {
    if let Some(d) = update.dmr_id {
        if d <= 0 || d > 16_777_215 {
            return Err(GaldraError::Config(
                "dmr_id must be blank or between 1 and 16777215 (24-bit)".to_string(),
            ));
        }
    }
    if let Some(ref s) = update.radio_affiliation {
        if s.len() > 128 {
            return Err(GaldraError::Config(
                "radio_affiliation exceeds 128 characters".to_string(),
            ));
        }
    }
    validate_address_lens(
        update.street.as_deref(),
        update.country.as_deref(),
        update.postal_code.as_deref(),
        update.region.as_deref(),
    )?;
    validate_social_ids(
        update.fluxer_id.as_deref(),
        update.discord_id.as_deref(),
        update.irc_id.as_deref(),
    )?;
    Ok(())
}

/// Apply a partial update to an existing contact (metadata only unless upsert key).
pub fn contact_update(
    db: &mut Db,
    id: &str,
    update: ContactUpdate,
) -> Result<Identity, GaldraError> {
    let _ = contact_get_by_id(db, id)?;
    validate_contact_update(&update)?;
    if update.display_name.is_none()
        && update.callsign.is_none()
        && update.email.is_none()
        && update.badge_number.is_none()
        && update.organisation.is_none()
        && update.department.is_none()
        && update.role.is_none()
        && update.note.is_none()
        && update.dmr_id.is_none()
        && update.radio_affiliation.is_none()
        && update.street.is_none()
        && update.country.is_none()
        && update.postal_code.is_none()
        && update.region.is_none()
        && update.fluxer_id.is_none()
        && update.discord_id.is_none()
        && update.irc_id.is_none()
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
                note = COALESCE(?9, note),
                dmr_id = COALESCE(?10, dmr_id),
                radio_affiliation = COALESCE(?11, radio_affiliation),
                street = COALESCE(?12, street),
                country = COALESCE(?13, country),
                postal_code = COALESCE(?14, postal_code),
                region = COALESCE(?15, region),
                fluxer_id = COALESCE(?16, fluxer_id),
                discord_id = COALESCE(?17, discord_id),
                irc_id = COALESCE(?18, irc_id)
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
                update.dmr_id,
                update.radio_affiliation,
                update.street,
                update.country,
                update.postal_code,
                update.region,
                update.fluxer_id,
                update.discord_id,
                update.irc_id,
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
        role, note, dmr_id, radio_affiliation, street, country, postal_code, region,
            fluxer_id, discord_id, irc_id, pgp_fingerprint, pgp_pubkey, fetched_at, expires_at, source
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

    let mut stmt = db
        .connection()
        .prepare(&sql)
        .map_err(GaldraError::Database)?;
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
            params![id, pubkey, fingerprint, source.as_str(), fetched_at, exp,],
        )
        .map_err(GaldraError::Database)?;
    Ok(())
}
