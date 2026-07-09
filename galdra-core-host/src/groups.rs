//! Group CRUD, membership, and expiry helpers.

use crate::contacts::Identity;
use crate::db::Db;
use crate::GaldraError;
use chrono::{DateTime, Utc};
use rusqlite::params;

/// Summary row for `group list`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GroupSummary {
    /// Unique group name.
    pub name: String,
    /// Number of members in the group table.
    pub member_count: usize,
}

/// One membership row with expiry information.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GroupMember {
    /// Referenced identity.
    pub identity: Identity,
    /// When the membership was added.
    pub added_at: DateTime<Utc>,
    /// Who added the member, if recorded.
    pub added_by: Option<String>,
    /// Membership expiry, if any.
    pub expires_at: Option<DateTime<Utc>>,
    /// True when membership or key is past expiry.
    pub is_expired: bool,
}

/// Full group metadata plus members.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GroupWithMembers {
    /// Group name.
    pub name: String,
    /// Human description.
    pub description: Option<String>,
    /// Hidden recipient PKESK mode.
    pub hidden_recipients: bool,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Creator label, if any.
    pub created_by: Option<String>,
    /// All members including expired rows.
    pub members: Vec<GroupMember>,
}

fn parse_dt_required(s: &str) -> Result<DateTime<Utc>, GaldraError> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| GaldraError::Serialise(e.to_string()))
}

fn membership_expired(expires_at: Option<DateTime<Utc>>) -> bool {
    match expires_at {
        None => false,
        Some(t) => t < Utc::now(),
    }
}

/// Create a new empty group with metadata.
pub fn group_create(
    db: &mut Db,
    name: &str,
    description: Option<&str>,
    hidden_recipients: bool,
) -> Result<(), GaldraError> {
    let now = Utc::now().to_rfc3339();
    db.connection_mut()
        .execute(
            r"INSERT INTO group_metadata (group_name, description, hidden_recipients, created_at, created_by)
            VALUES (?1, ?2, ?3, ?4, NULL)",
            params![name, description, hidden_recipients as i64, now,],
        )
        .map_err(GaldraError::Database)?;
    Ok(())
}

/// Load group metadata and every membership row.
pub fn group_get(db: &Db, name: &str) -> Result<GroupWithMembers, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT description, hidden_recipients, created_at, created_by
            FROM group_metadata WHERE group_name = ?1",
        )
        .map_err(GaldraError::Database)?;
    let (description, hidden, created_at_s, created_by): (
        Option<String>,
        i64,
        String,
        Option<String>,
    ) = stmt
        .query_row([name], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => GaldraError::GroupNotFound(name.to_string()),
            e => GaldraError::Database(e),
        })?;

    let created_at = parse_dt_required(&created_at_s)?;

    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT g.added_at, g.added_by, g.expires_at,
                i.id, i.display_name, i.callsign, i.email, i.badge_number, i.organisation,
                i.department, i.role, i.note, i.dmr_id, i.radio_affiliation, i.street,
                i.country, i.postal_code, i.region, i.fluxer_id, i.discord_id, i.irc_id,
                i.phone_number,
                i.pgp_fingerprint, i.pgp_pubkey, i.fetched_at, i.expires_at, i.source
            FROM groups g
            JOIN identities i ON i.id = g.identity_id
            WHERE g.group_name = ?1",
        )
        .map_err(GaldraError::Database)?;

    let rows = stmt
        .query_map([name], |row| {
            let added_at_s: String = row.get(0)?;
            let added_by: Option<String> = row.get(1)?;
            let mem_exp_s: Option<String> = row.get(2)?;
            let identity = crate::contacts::identity_from_row_offset(row, 3)?;

            let added_at = DateTime::parse_from_rfc3339(&added_at_s)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            let mem_exp = match &mem_exp_s {
                None => None,
                Some(s) => Some(
                    DateTime::parse_from_rfc3339(s)
                        .map(|d| d.with_timezone(&Utc))
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                ),
            };

            let is_expired = membership_expired(mem_exp) || key_expired(identity.expires_at);
            Ok(GroupMember {
                identity,
                added_at,
                added_by,
                expires_at: mem_exp,
                is_expired,
            })
        })
        .map_err(GaldraError::Database)?;

    let mut members = Vec::new();
    for r in rows {
        members.push(r.map_err(GaldraError::Database)?);
    }

    Ok(GroupWithMembers {
        name: name.to_string(),
        description,
        hidden_recipients: hidden != 0,
        created_at,
        created_by,
        members,
    })
}

fn key_expired(expires_at: Option<DateTime<Utc>>) -> bool {
    match expires_at {
        None => false,
        Some(t) => t < Utc::now(),
    }
}

/// Enumerate all groups with member counts.
pub fn group_list(db: &Db) -> Result<Vec<GroupSummary>, GaldraError> {
    let mut stmt = db
        .connection()
        .prepare(
            r"SELECT gm.group_name,
                (SELECT COUNT(*) FROM groups g WHERE g.group_name = gm.group_name)
            FROM group_metadata gm
            ORDER BY gm.group_name COLLATE NOCASE",
        )
        .map_err(GaldraError::Database)?;
    let rows = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok(GroupSummary {
                name,
                member_count: count as usize,
            })
        })
        .map_err(GaldraError::Database)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(GaldraError::Database)?);
    }
    Ok(out)
}

/// Add a member to a group, optionally with membership expiry.
pub fn group_add_member(
    db: &mut Db,
    group: &str,
    identity_id: &str,
    added_by: Option<&str>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<(), GaldraError> {
    let _ = group_get(db, group)?;
    let _ = crate::contacts::contact_get_by_id(db, identity_id)?;
    let now = Utc::now().to_rfc3339();
    let exp = expires_at.map(|t| t.to_rfc3339());
    db.connection_mut()
        .execute(
            r"INSERT INTO groups (group_name, identity_id, added_at, added_by, expires_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(group_name, identity_id) DO UPDATE SET
                added_at = excluded.added_at,
                added_by = excluded.added_by,
                expires_at = excluded.expires_at",
            params![group, identity_id, now, added_by, exp],
        )
        .map_err(GaldraError::Database)?;
    Ok(())
}

/// Remove a member from a group.
pub fn group_remove_member(db: &mut Db, group: &str, identity_id: &str) -> Result<(), GaldraError> {
    let n = db
        .connection_mut()
        .execute(
            "DELETE FROM groups WHERE group_name = ?1 AND identity_id = ?2",
            params![group, identity_id],
        )
        .map_err(GaldraError::Database)?;
    if n == 0 {
        return Err(GaldraError::GroupNotFound(format!("{group}/{identity_id}")));
    }
    Ok(())
}

/// Delete a group and its memberships.
pub fn group_delete(db: &mut Db, name: &str) -> Result<(), GaldraError> {
    let n = db
        .connection_mut()
        .execute("DELETE FROM group_metadata WHERE group_name = ?1", [name])
        .map_err(GaldraError::Database)?;
    if n == 0 {
        return Err(GaldraError::GroupNotFound(name.to_string()));
    }
    Ok(())
}

/// Return members whose membership is currently active (not expired).
pub fn group_active_members(db: &Db, name: &str) -> Result<Vec<Identity>, GaldraError> {
    let g = group_get(db, name)?;
    if g.members.is_empty() {
        return Ok(Vec::new());
    }
    let active: Vec<Identity> = g
        .members
        .iter()
        .filter(|m| !m.is_expired)
        .map(|m| m.identity.clone())
        .collect();
    if active.is_empty() {
        return Err(GaldraError::AllMembersExpired);
    }
    Ok(active)
}

/// Copy members from `source` into `target` (active memberships only).
pub fn group_add_from_group(
    db: &mut Db,
    target: &str,
    source: &str,
    added_by: Option<&str>,
) -> Result<usize, GaldraError> {
    let src = group_get(db, source)?;
    let mut added = 0usize;
    for m in src.members {
        if m.is_expired {
            continue;
        }
        group_add_member(db, target, &m.identity.id, added_by, m.expires_at)?;
        added += 1;
    }
    Ok(added)
}

/// Update group metadata fields.
pub fn group_edit(
    db: &mut Db,
    name: &str,
    description: Option<&str>,
    hidden_recipients: Option<bool>,
) -> Result<(), GaldraError> {
    let _ = group_get(db, name)?;
    if description.is_none() && hidden_recipients.is_none() {
        return Ok(());
    }
    db.connection_mut()
        .execute(
            r"UPDATE group_metadata SET
                description = COALESCE(?2, description),
                hidden_recipients = COALESCE(?3, hidden_recipients)
            WHERE group_name = ?1",
            params![name, description, hidden_recipients.map(|b| b as i64),],
        )
        .map_err(GaldraError::Database)?;
    Ok(())
}
