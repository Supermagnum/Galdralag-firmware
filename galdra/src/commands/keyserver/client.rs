//! Fulla-style HTTP registry helpers and response types.

use galdra_core_host::config::RegistryKeyserverConfig;
use galdra_core_host::GaldraError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const REGISTRY_PUSH_PATH: &str = "/api/v1/keys";
const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Response body from `POST /api/v1/keys`.
#[derive(Debug, Deserialize)]
pub struct PushResponse {
    pub status: String,
    pub fingerprint: Option<String>,
    pub message: Option<String>,
    pub reason: Option<String>,
}

/// Public key row returned by `GET /keys/...`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyRecord {
    pub fingerprint: String,
    pub armored_key: String,
    pub email: String,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub callsign: Option<String>,
    #[serde(default)]
    pub dmr_id: Option<u32>,
    #[serde(default)]
    pub radio_affiliation: Option<String>,
    #[serde(default)]
    pub fluxer_id: Option<String>,
    #[serde(default)]
    pub discord_id: Option<String>,
    #[serde(default)]
    pub irc_id: Option<String>,
    #[serde(default)]
    pub street: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    pub submitted_at: String,
    pub status: String,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum FetchKeysBody {
    One(KeyRecord),
    Many(Vec<KeyRecord>),
}

pub fn registry_http_client() -> Result<reqwest::blocking::Client, GaldraError> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| {
            tracing::debug!(error = %e, "failed to build registry HTTP client");
            GaldraError::Config("could not initialise HTTP client for registry".to_string())
        })
}

pub fn trimmed_registry_base(url: &str) -> Result<String, GaldraError> {
    let t = url.trim();
    if t.is_empty() {
        return Err(GaldraError::Config(
            "registry base URL must not be empty".to_string(),
        ));
    }
    Ok(t.trim_end_matches('/').to_string())
}

pub fn push_url(base: &str) -> Result<String, GaldraError> {
    let b = trimmed_registry_base(base)?;
    Ok(format!("{b}{REGISTRY_PUSH_PATH}"))
}

pub fn fingerprint_lookup_url(base: &str, fp: &str) -> Result<String, GaldraError> {
    let b = trimmed_registry_base(base)?;
    Ok(format!("{b}/keys/{fp}"))
}

pub fn email_lookup_url(base: &str, email: &str) -> Result<String, GaldraError> {
    let b = trimmed_registry_base(base)?;
    let mut u =
        reqwest::Url::parse(&format!("{b}/keys")).map_err(|e| GaldraError::Config(format!(
            "invalid registry URL: {e}; set `--keyserver-url`, GALDRA_KEYSERVER_URL, or [keyserver] url"
        )))?;
    u.query_pairs_mut().append_pair("email", email);
    Ok(u.to_string())
}

const ENV_REGISTRY_URL: &str = "GALDRA_KEYSERVER_URL";

/// Resolve registry URL: CLI flag → non-empty trimmed `GALDRA_KEYSERVER_URL` → `[keyserver].url`.
pub fn resolve_registry_url(
    flag: Option<&str>,
    cfg: Option<&RegistryKeyserverConfig>,
) -> Result<String, GaldraError> {
    let env_candidate = std::env::var(ENV_REGISTRY_URL).ok();
    resolve_registry_sources(flag, cfg, env_candidate.as_deref())
}

/// Resolve with an explicit candidate for the environment-variable value (`GALDRA_KEYSERVER_URL`);
/// handy for deterministic tests without touching the real process environment.
pub fn resolve_registry_sources(
    flag: Option<&str>,
    cfg: Option<&RegistryKeyserverConfig>,
    env_value: Option<&str>,
) -> Result<String, GaldraError> {
    if let Some(u) = flag {
        let t = u.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    if let Some(v) = env_value {
        let t = v.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    if let Some(c) = cfg {
        let t = c.url.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    Err(GaldraError::Config(
        "no registry URL configured — pass `--keyserver-url`, set environment variable \
         GALDRA_KEYSERVER_URL, or add a [keyserver] section with url = \"...\" to your config file"
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use galdra_core_host::config::RegistryKeyserverConfig;

    #[test]
    fn resolve_order_flag_env_config() {
        let cfg_some = RegistryKeyserverConfig {
            url: "https://from-config.invalid".into(),
        };

        assert_eq!(
            resolve_registry_sources(
                Some("https://from-flag.invalid"),
                Some(&cfg_some),
                Some("https://from-env.invalid"),
            )
            .unwrap(),
            "https://from-flag.invalid"
        );

        assert_eq!(
            resolve_registry_sources(None, Some(&cfg_some), Some("https://from-env.invalid")).unwrap(),
            "https://from-env.invalid"
        );

        assert_eq!(
            resolve_registry_sources(None, Some(&cfg_some), Some("")).unwrap(),
            "https://from-config.invalid"
        );

        assert_eq!(
            resolve_registry_sources(None, Some(&cfg_some), None).unwrap(),
            "https://from-config.invalid"
        );
    }

    #[test]
    fn blank_flag_env_skips_until_config_when_present() {
        let cfg_some = RegistryKeyserverConfig {
            url: "https://from-config.invalid".into(),
        };

        match resolve_registry_sources(Some(" "), Some(&cfg_some), Some("")) {
            Ok(v) => assert_eq!(v, "https://from-config.invalid"),
            Err(_) => panic!("unexpected"),
        }
    }

    #[test]
    fn blank_env_fallback_to_config() {
        let cfg_some = RegistryKeyserverConfig {
            url: "https://from-config.invalid".into(),
        };

        match resolve_registry_sources(None, Some(&cfg_some), Some(" \t ")) {
            Ok(v) => assert_eq!(v, "https://from-config.invalid"),
            Err(_) => panic!("unexpected"),
        }
    }

    #[test]
    fn blanks_fail_when_no_config_section() {
        assert!(resolve_registry_sources(Some("\n"), None, None).is_err());
        assert!(resolve_registry_sources(Some(" "), None, None).is_err());
    }
    #[test]
    fn resolve_errors_when_missing() {
        assert!(resolve_registry_sources(None, None, None).is_err());
        assert!(resolve_registry_sources(None, None, Some("")).is_err());
        assert!(resolve_registry_sources(None, None, Some("\n")).is_err());
    }

    #[test]
    fn push_url_formats() {
        assert_eq!(
            push_url("https://keys.example.com/").unwrap(),
            "https://keys.example.com/api/v1/keys"
        );
    }
}
