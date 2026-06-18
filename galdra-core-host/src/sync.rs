//! Offline database export/import for contacts and groups (no private keys).
//!
//! Sync packages are SQLite databases containing the same `identities`, `groups`, and
//! `group_metadata` schema as the main application database, without `audit_log` or `config`.

use std::collections::HashSet;
use std::path::Path;

use rusqlite::Connection;

use crate::db::Db;
use crate::GaldraError;

/// How to apply a sync package to the local database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncImportMode {
    /// Upsert rows from the package by primary key.
    Merge,
    /// Remove existing contacts and groups, then copy from the package.
    Replace,
}

fn sqlite_path_for_attach(path: &Path) -> Result<String, GaldraError> {
    let p = std::fs::canonicalize(path).map_err(GaldraError::Io)?;
    Ok(p.to_string_lossy().replace('\\', "/"))
}

fn copy_table(src: &Connection, dst: &Connection, table: &str) -> Result<(), GaldraError> {
    let mut stmt = src
        .prepare(&format!("SELECT * FROM {table}"))
        .map_err(GaldraError::Database)?;
    let cols = stmt.column_count();
    if cols == 0 {
        return Ok(());
    }
    let col_names: Vec<String> = (0..cols)
        .map(|i| stmt.column_name(i).map(|s| s.to_string()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(GaldraError::Database)?;
    let ph = (0..cols).map(|_| "?").collect::<Vec<_>>().join(",");
    let insert_sql = format!(
        "INSERT INTO {table} ({}) VALUES ({ph})",
        col_names.join(",")
    );
    let mut rows = stmt.query([]).map_err(GaldraError::Database)?;
    let mut insert = dst.prepare(&insert_sql).map_err(GaldraError::Database)?;
    while let Some(row) = rows.next().map_err(GaldraError::Database)? {
        let values: Vec<rusqlite::types::Value> = (0..cols)
            .map(|i| row.get::<_, rusqlite::types::Value>(i))
            .collect::<Result<Vec<_>, _>>()
            .map_err(GaldraError::Database)?;
        insert
            .execute(rusqlite::params_from_iter(&values))
            .map_err(GaldraError::Database)?;
    }
    Ok(())
}

fn pragma_identity_columns(conn: &Connection, pragma: &str) -> Result<Vec<String>, GaldraError> {
    let mut stmt = conn.prepare(pragma).map_err(GaldraError::Database)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(GaldraError::Database)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(GaldraError::Database)?);
    }
    Ok(out)
}

fn import_identities_sql(conn: &Connection, or_replace: bool) -> Result<String, GaldraError> {
    let dst_cols = pragma_identity_columns(conn, "PRAGMA main.table_info(identities)")?;
    let pkg_cols = pragma_identity_columns(conn, "PRAGMA pkg.table_info(identities)")?;
    let pkg_has: HashSet<String> = pkg_cols.into_iter().collect();
    let select_exprs: Vec<String> = dst_cols
        .iter()
        .map(|c| {
            if pkg_has.contains(c) {
                format!("pkg.identities.{c}")
            } else {
                "NULL".into()
            }
        })
        .collect();
    let cols_csv = dst_cols.join(", ");
    let sel_csv = select_exprs.join(", ");
    let verb = if or_replace {
        "INSERT OR REPLACE"
    } else {
        "INSERT"
    };
    Ok(format!(
        "{verb} INTO identities ({cols_csv}) SELECT {sel_csv} FROM pkg.identities"
    ))
}

/// Export contacts and groups to a new SQLite file at `export_path`.
///
/// Data is read from the open `db` handle (no second connection to the same file), so export
/// works while the main database is in use. `export_path` is overwritten if it already exists.
pub fn sync_export(db: &Db, export_path: &Path) -> Result<(), GaldraError> {
    if let Some(parent) = export_path.parent() {
        std::fs::create_dir_all(parent).map_err(GaldraError::Io)?;
    }
    if export_path.exists() {
        std::fs::remove_file(export_path).map_err(GaldraError::Io)?;
    }

    let mut out = Db::open(export_path, None)?;
    let src = db.connection();
    let conn = out.connection_mut();
    let tx = conn.transaction().map_err(GaldraError::Database)?;
    tx.execute_batch("PRAGMA foreign_keys = OFF;")
        .map_err(GaldraError::Database)?;
    copy_table(src, &tx, "identities")?;
    copy_table(src, &tx, "group_metadata")?;
    copy_table(src, &tx, "groups")?;
    tx.execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(GaldraError::Database)?;
    tx.commit().map_err(GaldraError::Database)?;
    Ok(())
}

/// Import a sync package produced by [`sync_export`].
pub fn sync_import(
    db: &mut Db,
    package_path: &Path,
    mode: SyncImportMode,
) -> Result<(), GaldraError> {
    let pkg = sqlite_path_for_attach(package_path)?;
    let conn = db.connection_mut();
    conn.execute("ATTACH DATABASE ? AS pkg", [&pkg])
        .map_err(GaldraError::Database)?;
    let tx = conn.transaction().map_err(GaldraError::Database)?;
    match mode {
        SyncImportMode::Replace => {
            tx.execute_batch("PRAGMA foreign_keys = OFF;")
                .map_err(GaldraError::Database)?;
            tx.execute("DELETE FROM groups", [])
                .map_err(GaldraError::Database)?;
            tx.execute("DELETE FROM group_metadata", [])
                .map_err(GaldraError::Database)?;
            tx.execute("DELETE FROM identities", [])
                .map_err(GaldraError::Database)?;
            let ins = import_identities_sql(&tx, false)?;
            tx.execute(&ins, []).map_err(GaldraError::Database)?;
            tx.execute(
                "INSERT INTO group_metadata SELECT * FROM pkg.group_metadata",
                [],
            )
            .map_err(GaldraError::Database)?;
            tx.execute("INSERT INTO groups SELECT * FROM pkg.groups", [])
                .map_err(GaldraError::Database)?;
            tx.execute_batch("PRAGMA foreign_keys = ON;")
                .map_err(GaldraError::Database)?;
        }
        SyncImportMode::Merge => {
            let ins = import_identities_sql(&tx, true)?;
            tx.execute(&ins, []).map_err(GaldraError::Database)?;
            tx.execute(
                "INSERT OR REPLACE INTO group_metadata SELECT * FROM pkg.group_metadata",
                [],
            )
            .map_err(GaldraError::Database)?;
            tx.execute("INSERT OR REPLACE INTO groups SELECT * FROM pkg.groups", [])
                .map_err(GaldraError::Database)?;
        }
    }
    tx.commit().map_err(GaldraError::Database)?;
    conn.execute("DETACH DATABASE pkg", [])
        .map_err(GaldraError::Database)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::NewContact;
    use crate::db::Db;

    #[test]
    fn export_import_merge() {
        let dir = tempfile::tempdir().unwrap();
        let main_path = dir.path().join("main.db");
        let mut db = Db::open(&main_path, None).unwrap();
        let id = crate::contacts::contact_add(
            &mut db,
            NewContact {
                display_name: "A".to_string(),
                callsign: None,
                email: None,
                badge_number: None,
                organisation: None,
                department: None,
                role: None,
                note: None,
                dmr_id: None,
                radio_affiliation: None,
                street: None,
                country: None,
                postal_code: None,
                region: None,
            },
        )
        .unwrap();
        crate::groups::group_create(&mut db, "g1", None, false).unwrap();
        crate::groups::group_add_member(&mut db, "g1", &id.id, None, None).unwrap();

        let export_path = dir.path().join("sync.db");
        sync_export(&db, &export_path).unwrap();

        let other_path = dir.path().join("other.db");
        let mut other = Db::open(&other_path, None).unwrap();
        sync_import(&mut other, &export_path, SyncImportMode::Merge).unwrap();

        let g = crate::groups::group_get(&other, "g1").unwrap();
        assert_eq!(g.members.len(), 1);
        assert_eq!(g.members[0].identity.id, id.id);
    }

    #[test]
    fn import_replace_clears() {
        let dir = tempfile::tempdir().unwrap();
        let main_path = dir.path().join("main.db");
        let mut db = Db::open(&main_path, None).unwrap();
        let id = crate::contacts::contact_add(
            &mut db,
            NewContact {
                display_name: "A".to_string(),
                callsign: None,
                email: None,
                badge_number: None,
                organisation: None,
                department: None,
                role: None,
                note: None,
                dmr_id: None,
                radio_affiliation: None,
                street: None,
                country: None,
                postal_code: None,
                region: None,
            },
        )
        .unwrap();
        crate::groups::group_create(&mut db, "g1", None, false).unwrap();
        crate::groups::group_add_member(&mut db, "g1", &id.id, None, None).unwrap();

        let export_path = dir.path().join("sync.db");
        sync_export(&db, &export_path).unwrap();

        let id2 = crate::contacts::contact_add(
            &mut db,
            NewContact {
                display_name: "B".to_string(),
                callsign: None,
                email: None,
                badge_number: None,
                organisation: None,
                department: None,
                role: None,
                note: None,
                dmr_id: None,
                radio_affiliation: None,
                street: None,
                country: None,
                postal_code: None,
                region: None,
            },
        )
        .unwrap();
        assert_ne!(id.id, id2.id);

        sync_import(&mut db, &export_path, SyncImportMode::Replace).unwrap();

        let list = crate::contacts::contact_list(
            &db,
            crate::contacts::ContactFilter {
                expired: false,
                organisation: None,
                role: None,
            },
        )
        .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id.id);
    }
}
