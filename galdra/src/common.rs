//! Shared helpers for database access, configuration, PIN handling, and output formatting.

use galdra_core_host::config::{
    database_key_from_env, default_config_path, default_database_path, load_config, Config,
};
use galdra_core_host::contacts::{self, ContactFilter, Identity};
use galdra_core_host::db::Db;
use galdra_core_host::device::PinBuffer;
use galdra_core_host::GaldraError;
use std::io::Write;

/// Global output mode for structured CLI output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputMode {
    /// Human-readable table output.
    #[default]
    Human,
    /// Pretty-printed JSON.
    Json,
}

/// Resolve the database path from CLI override and configuration (same rules as [`open_database`]).
pub fn resolve_database_path(
    config: &Config,
    db_override: Option<&std::path::Path>,
) -> Result<std::path::PathBuf, GaldraError> {
    if let Some(p) = db_override {
        return Ok(p.to_path_buf());
    }
    if let Some(p) = &config.database_path {
        return Ok(p.clone());
    }
    default_database_path()
}

/// Open the SQLite database using config and CLI overrides.
pub fn open_database(
    config: &Config,
    db_override: Option<&std::path::Path>,
) -> Result<Db, GaldraError> {
    let path = resolve_database_path(config, db_override)?;
    let key = database_key_from_env(config)?;
    Db::open(&path, key.as_deref())
}

/// Load configuration from disk (or defaults) using an optional override path.
pub fn load_app_config(path: Option<&std::path::Path>) -> Result<Config, GaldraError> {
    let p = if let Some(p) = path {
        p.to_path_buf()
    } else {
        default_config_path()?
    };
    load_config(&p)
}

/// Prompt for a PIN using `rpassword` and validate via [`PinBuffer`].
pub fn prompt_pin(prompt: &str) -> Result<PinBuffer, GaldraError> {
    let pin = rpassword::prompt_password(prompt).map_err(GaldraError::Io)?;
    PinBuffer::new(pin)
}

/// Print key expiry warnings for contacts whose keys expire within the configured window.
pub fn print_expiry_warnings(db: &Db, config: &Config, quiet: bool) -> Result<(), GaldraError> {
    if quiet {
        return Ok(());
    }
    let warn_before =
        chrono::Utc::now() + chrono::Duration::days(i64::from(config.key_expiry_warn_days));
    let list = contacts::contact_list(
        db,
        ContactFilter {
            expired: false,
            organisation: None,
            role: None,
        },
    )?;
    let mut near: Vec<&Identity> = Vec::new();
    for c in &list {
        if let Some(exp) = c.expires_at {
            if exp <= warn_before && exp > chrono::Utc::now() {
                near.push(c);
            }
        }
    }
    if near.is_empty() {
        return Ok(());
    }
    eprintln!(
        "Warning: the following contacts have keys expiring within {} days:",
        config.key_expiry_warn_days
    );
    for c in near {
        eprintln!(
            "  {} ({}) expires {}",
            if c.display_name.is_empty() {
                c.email.as_deref().unwrap_or(&c.id)
            } else {
                c.display_name.as_str()
            },
            c.id,
            c.expires_at.map(|t| t.to_rfc3339()).unwrap_or_default()
        );
    }
    Ok(())
}

/// Resolve a contact identifier (UUID, callsign, e-mail, Fluxer id, Discord id, or IRC id) to a row.
pub fn resolve_identity(db: &Db, id: &str) -> Result<Identity, GaldraError> {
    if let Ok(c) = contacts::contact_get_by_id(db, id) {
        return Ok(c);
    }
    if let Ok(c) = contacts::contact_get_by_callsign(db, id) {
        return Ok(c);
    }
    if let Ok(c) = contacts::contact_get_by_email(db, id) {
        return Ok(c);
    }
    if let Ok(c) = contacts::contact_get_by_fluxer_id(db, id) {
        return Ok(c);
    }
    if let Ok(c) = contacts::contact_get_by_discord_id(db, id) {
        return Ok(c);
    }
    contacts::contact_get_by_irc_id(db, id)
}

/// Exit status mapping for CLI errors.
pub fn exit_code(err: &GaldraError) -> i32 {
    match err {
        GaldraError::UserAborted => 2,
        _ => 1,
    }
}

/// Serialise a value as JSON for `--output json` mode.
pub fn print_json<T: serde::Serialize>(value: &T) -> Result<(), GaldraError> {
    let s =
        serde_json::to_string_pretty(value).map_err(|e| GaldraError::Serialise(e.to_string()))?;
    println!("{}", s);
    Ok(())
}

/// Flush stderr (used before reading confirmation lines).
pub fn flush_stderr() -> Result<(), GaldraError> {
    std::io::stderr().flush().map_err(GaldraError::Io)
}
