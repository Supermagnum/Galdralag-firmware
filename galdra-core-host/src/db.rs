//! SQLite connection wrapper and migration runner.

use crate::GaldraError;
use chrono::Utc;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use std::path::Path;

/// Embedded migration: version number and SQL body.
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/001_initial.sql")),
    (2, include_str!("../migrations/002_audit_prev_hash.sql")),
    (3, include_str!("../migrations/003_user_profiles.sql")),
    (4, include_str!("../migrations/004_ephemeral_offers.sql")),
];

/// OpenPGP contacts, groups, audit, and config store.
pub struct Db {
    conn: Connection,
}

impl Db {
    /// Open or create the database at `path`, run pending migrations, and return a handle.
    ///
    /// When `sqlcipher_key` is `Some`, sets the SQLCipher key via `PRAGMA key` before any other
    /// access (same passphrase must be used on every open). When `None`, the file is treated as
    /// plaintext (compatible with databases created before encryption was enabled).
    pub fn open(path: &Path, sqlcipher_key: Option<&str>) -> Result<Self, GaldraError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(GaldraError::Io)?;
        }
        let conn = Connection::open(path).map_err(GaldraError::Database)?;
        if let Some(k) = sqlcipher_key {
            conn
                .pragma_update(None, "key", k)
                .map_err(GaldraError::Database)?;
        }
        let mut db = Db { conn };
        db.run_migrations()?;
        Ok(db)
    }

    /// Open an in-memory database and apply migrations (for tests).
    pub fn open_in_memory() -> Result<Self, GaldraError> {
        let conn = Connection::open_in_memory().map_err(GaldraError::Database)?;
        let mut db = Db { conn };
        db.run_migrations()?;
        Ok(db)
    }

    /// Borrow the underlying `rusqlite` connection.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Mutable access to the connection (for transactions and mutating APIs).
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    fn run_migrations(&mut self) -> Result<(), GaldraError> {
        self.conn
            .execute_batch(
                r"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL,
                applied_at TEXT NOT NULL
            );
            ",
            )
            .map_err(GaldraError::Database)?;

        for &(version, sql) in MIGRATIONS {
            let applied: Option<i64> = self
                .conn
                .query_row(
                    "SELECT 1 FROM schema_migrations WHERE version = ?1",
                    [version],
                    |r| r.get(0),
                )
                .optional()
                .map_err(GaldraError::Database)?;

            if applied.is_some() {
                continue;
            }

            let tx = self.conn.transaction().map_err(GaldraError::Database)?;
            tx.execute_batch(sql).map_err(GaldraError::Database)?;
            let now = Utc::now().to_rfc3339();
            tx.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                rusqlite::params![version, now],
            )
            .map_err(GaldraError::Database)?;
            tx.commit().map_err(GaldraError::Database)?;
        }
        Ok(())
    }
}
