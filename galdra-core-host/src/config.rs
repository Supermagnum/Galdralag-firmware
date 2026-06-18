//! Configuration file loading with safe defaults.

use crate::GaldraError;
use serde::Deserialize;
use std::path::PathBuf;

/// Top-level configuration loaded from `config.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Override path to the SQLite database file.
    pub database_path: Option<PathBuf>,
    /// HKP / WKD related settings.
    #[serde(default)]
    pub keyservers: KeyserverConfig,
    /// Optional LDAP directory settings.
    pub ldap: Option<LdapConfig>,
    /// When set, the database passphrase is read from this environment variable (never from the config file).
    #[serde(default)]
    pub database_key_env: Option<String>,
    /// Days before key expiry when startup warnings are shown (default 30).
    #[serde(default = "default_key_expiry_warn_days")]
    pub key_expiry_warn_days: u32,
}

fn default_key_expiry_warn_days() -> u32 {
    30
}

/// Keyserver list and query timeout.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct KeyserverConfig {
    /// HKP servers to try in order (must use `hkps://`).
    #[serde(default = "default_keyservers")]
    pub servers: Vec<String>,
    /// Per-request timeout in seconds (default 10).
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

fn default_keyservers() -> Vec<String> {
    vec![
        "hkps://keys.openpgp.org".to_string(),
        "hkps://keyserver.ubuntu.com".to_string(),
        "hkps://pgp.mit.edu".to_string(),
    ]
}

fn default_timeout_seconds() -> u64 {
    10
}

impl Default for KeyserverConfig {
    fn default() -> Self {
        KeyserverConfig {
            servers: default_keyservers(),
            timeout_seconds: default_timeout_seconds(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            database_path: None,
            keyservers: KeyserverConfig::default(),
            ldap: None,
            database_key_env: None,
            key_expiry_warn_days: default_key_expiry_warn_days(),
        }
    }
}

/// LDAP / Active Directory settings (password is never stored).
#[derive(Debug, Clone, Deserialize)]
pub struct LdapConfig {
    /// LDAP URL (prefer `ldaps://`).
    pub url: String,
    /// Search base DN.
    pub base_dn: String,
    /// Bind DN for authenticated search.
    pub bind_dn: String,
    /// Environment variable name that holds the bind password.
    pub bind_pw_env: String,
    /// Filter template with `{query}` placeholder.
    pub user_filter: String,
    /// Attribute containing the certificate or key blob.
    pub key_attribute: String,
    /// Allow plain LDAP without TLS (emits a runtime warning).
    #[serde(default)]
    pub allow_plain_ldap: bool,
}

/// Default database path for the current platform.
pub fn default_database_path() -> Result<PathBuf, GaldraError> {
    #[cfg(target_os = "linux")]
    {
        let base = data_dir_linux()?;
        Ok(base.join("galdra").join("galdra.db"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = home_dir()?;
        Ok(home
            .join("Library")
            .join("Application Support")
            .join("galdra")
            .join("galdra.db"))
    }
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").map_err(|_| {
            GaldraError::Config("APPDATA environment variable is not set".to_string())
        })?;
        Ok(PathBuf::from(appdata).join("galdra").join("galdra.db"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let home = home_dir()?;
        Ok(home
            .join(".local")
            .join("share")
            .join("galdra")
            .join("galdra.db"))
    }
}

/// Default configuration file path for the current platform.
pub fn default_config_path() -> Result<PathBuf, GaldraError> {
    #[cfg(target_os = "linux")]
    {
        let home = home_dir()?;
        Ok(home.join(".config").join("galdra").join("config.toml"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = home_dir()?;
        Ok(home
            .join("Library")
            .join("Application Support")
            .join("galdra")
            .join("config.toml"))
    }
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").map_err(|_| {
            GaldraError::Config("APPDATA environment variable is not set".to_string())
        })?;
        Ok(PathBuf::from(appdata).join("galdra").join("config.toml"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let home = home_dir()?;
        Ok(home.join(".config").join("galdra").join("config.toml"))
    }
}

fn home_dir() -> Result<PathBuf, GaldraError> {
    #[cfg(unix)]
    {
        std::env::var("HOME")
            .map(PathBuf::from)
            .map_err(|_| GaldraError::Config("HOME environment variable is not set".to_string()))
    }
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE")
            .map(PathBuf::from)
            .map_err(|_| {
                GaldraError::Config("USERPROFILE environment variable is not set".to_string())
            })
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::env::var("HOME")
            .map(PathBuf::from)
            .map_err(|_| GaldraError::Config("HOME environment variable is not set".to_string()))
    }
}

#[cfg(target_os = "linux")]
fn data_dir_linux() -> Result<PathBuf, GaldraError> {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg));
        }
    }
    let home = home_dir()?;
    Ok(home.join(".local").join("share"))
}

/// When [`Config::database_key_env`] is set, read the SQLCipher passphrase from that environment
/// variable. Returns `None` if encryption is not configured.
pub fn database_key_from_env(config: &Config) -> Result<Option<String>, GaldraError> {
    match &config.database_key_env {
        None => Ok(None),
        Some(name) => {
            let v = std::env::var(name).map_err(|_| {
                GaldraError::Config(format!(
                    "database_key_env names {name:?} but that environment variable is not set"
                ))
            })?;
            if v.is_empty() {
                return Err(GaldraError::Config(format!(
                    "environment variable {name} must not be empty when database encryption is enabled"
                )));
            }
            Ok(Some(v))
        }
    }
}

/// Load configuration from `path`, or return defaults if the file is missing.
pub fn load_config(path: &std::path::Path) -> Result<Config, GaldraError> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let bytes = std::fs::read(path).map_err(GaldraError::Io)?;
    let text = String::from_utf8_lossy(&bytes);
    toml::from_str::<Config>(&text).map_err(|e| GaldraError::Config(e.to_string()))
}
