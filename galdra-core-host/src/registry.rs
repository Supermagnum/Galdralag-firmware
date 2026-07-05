//! Fulla-compatible HTTP registry URL resolution and geographic failover.
//!
//! Clients reach each Fulla node's public `KEYSERVER_BASE_URL`, not the private mesh sync port
//! (`sync_api_port`). Node labels mirror Fulla `[[replication.mesh.peers]].region` / `node_id`.

use crate::config::{RegistryKeyserverConfig, RegistryNodeConfig, MAX_REGISTRY_NODES};
use crate::GaldraError;

/// One registry endpoint to try (in config order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEndpoint {
    pub region: Option<String>,
    pub url: String,
}

/// Environment variable override for a single registry base URL.
pub const ENV_REGISTRY_URL: &str = "GALDRA_KEYSERVER_URL";

/// Trim and validate a registry base URL.
pub fn trimmed_registry_base(url: &str) -> Result<String, GaldraError> {
    let t = url.trim();
    if t.is_empty() {
        return Err(GaldraError::Config(
            "registry base URL must not be empty".to_string(),
        ));
    }
    Ok(t.trim_end_matches('/').to_string())
}

/// Returns false when `[keyserver] enabled = false`.
pub fn ensure_registry_enabled(cfg: &RegistryKeyserverConfig) -> Result<(), GaldraError> {
    if cfg.enabled {
        Ok(())
    } else {
        Err(GaldraError::Config(
            "[keyserver] enabled = false — set enabled = true to use the registry".to_string(),
        ))
    }
}

/// Ordered endpoints from config: `nodes` when non-empty, otherwise the legacy `url` field.
pub fn endpoints_from_config(cfg: &RegistryKeyserverConfig) -> Result<Vec<RegistryEndpoint>, GaldraError> {
    ensure_registry_enabled(cfg)?;
    let mut out = Vec::new();
    if cfg.nodes.is_empty() {
        out.push(RegistryEndpoint {
            region: None,
            url: trimmed_registry_base(&cfg.url)?,
        });
    } else {
        for node in &cfg.nodes {
            out.push(endpoint_from_node(node)?);
        }
    }
    if out.is_empty() {
        return Err(GaldraError::Config(
            "[keyserver] has no url or nodes configured".to_string(),
        ));
    }
    if out.len() > MAX_REGISTRY_NODES {
        return Err(GaldraError::Config(format!(
            "[keyserver] supports at most {MAX_REGISTRY_NODES} geographic nodes"
        )));
    }
    Ok(out)
}

fn endpoint_from_node(node: &RegistryNodeConfig) -> Result<RegistryEndpoint, GaldraError> {
    let region = node.region.trim();
    if region.is_empty() {
        return Err(GaldraError::Config(
            "each [[keyserver.nodes]] entry requires a non-empty region".to_string(),
        ));
    }
    if let Some(id) = &node.node_id {
        if id.trim().is_empty() {
            return Err(GaldraError::Config(
                "keyserver node_id must be omitted or non-empty".to_string(),
            ));
        }
    }
    Ok(RegistryEndpoint {
        region: Some(region.to_string()),
        url: trimmed_registry_base(&node.url)?,
    })
}

/// Resolved registry targets for push/fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryResolution {
    pub endpoints: Vec<RegistryEndpoint>,
    /// When true, try the next endpoint on transport / gateway errors.
    pub failover: bool,
    pub timeout_seconds: u64,
}

/// Resolve registry endpoints: CLI flag → `GALDRA_KEYSERVER_URL` → `[keyserver]` config.
///
/// A non-empty flag or environment value selects a **single** URL and disables config failover.
pub fn resolve_registry(
    flag: Option<&str>,
    cfg: Option<&RegistryKeyserverConfig>,
    env_value: Option<&str>,
) -> Result<RegistryResolution, GaldraError> {
    if let Some(u) = flag {
        let t = u.trim();
        if !t.is_empty() {
            return Ok(RegistryResolution {
                endpoints: vec![RegistryEndpoint {
                    region: None,
                    url: trimmed_registry_base(t)?,
                }],
                failover: false,
                timeout_seconds: default_timeout_from_cfg(cfg),
            });
        }
    }
    if let Some(v) = env_value {
        let t = v.trim();
        if !t.is_empty() {
            return Ok(RegistryResolution {
                endpoints: vec![RegistryEndpoint {
                    region: None,
                    url: trimmed_registry_base(t)?,
                }],
                failover: false,
                timeout_seconds: default_timeout_from_cfg(cfg),
            });
        }
    }
    let cfg = cfg.ok_or_else(|| {
        GaldraError::Config(
            "no registry URL configured — pass `--keyserver-url`, set environment variable \
             GALDRA_KEYSERVER_URL, or add a [keyserver] section with url or [[keyserver.nodes]] \
             to your config file"
                .to_string(),
        )
    })?;
    let endpoints = endpoints_from_config(cfg)?;
    let failover = cfg.failover && endpoints.len() > 1;
    Ok(RegistryResolution {
        endpoints,
        failover,
        timeout_seconds: cfg.timeout_seconds,
    })
}

fn default_timeout_from_cfg(cfg: Option<&RegistryKeyserverConfig>) -> u64 {
    cfg.map(|c| c.timeout_seconds).unwrap_or(30)
}

/// First URL in the resolved list (backward-compatible helper).
pub fn resolve_registry_url(
    flag: Option<&str>,
    cfg: Option<&RegistryKeyserverConfig>,
    env_value: Option<&str>,
) -> Result<String, GaldraError> {
    resolve_registry(flag, cfg, env_value)?
        .endpoints
        .first()
        .map(|e| e.url.clone())
        .ok_or_else(|| GaldraError::Config("no registry URL resolved".to_string()))
}

/// Whether to try the next geographic node after a failed attempt.
pub fn should_failover_after_http(status: u16, failover_enabled: bool) -> bool {
    if !failover_enabled {
        return false;
    }
    matches!(status, 502 | 503 | 504 | 429)
}

/// Application-level responses that must not trigger failover (same body on every replica).
pub fn is_registry_application_status(status: u16) -> bool {
    matches!(status, 400 | 401 | 403 | 404 | 409 | 422)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RegistryKeyserverConfig;

    fn sample_cfg() -> RegistryKeyserverConfig {
        RegistryKeyserverConfig {
            url: "https://primary.invalid".into(),
            enabled: true,
            failover: true,
            timeout_seconds: 15,
            nodes: vec![],
        }
    }

    #[test]
    fn resolve_order_flag_env_config() {
        let cfg = sample_cfg();
        assert_eq!(
            resolve_registry_url(
                Some("https://from-flag.invalid"),
                Some(&cfg),
                Some("https://from-env.invalid"),
            )
            .unwrap(),
            "https://from-flag.invalid"
        );
        assert_eq!(
            resolve_registry_url(None, Some(&cfg), Some("https://from-env.invalid")).unwrap(),
            "https://from-env.invalid"
        );
        assert_eq!(
            resolve_registry_url(None, Some(&cfg), None).unwrap(),
            "https://primary.invalid"
        );
    }

    #[test]
    fn flag_disables_failover_even_with_many_nodes() {
        let mut cfg = sample_cfg();
        cfg.nodes = vec![
            RegistryNodeConfig {
                region: "A".into(),
                node_id: None,
                url: "https://a.invalid".into(),
            },
            RegistryNodeConfig {
                region: "B".into(),
                node_id: None,
                url: "https://b.invalid".into(),
            },
        ];
        let r = resolve_registry(Some("https://only.invalid"), Some(&cfg), None).unwrap();
        assert_eq!(r.endpoints.len(), 1);
        assert!(!r.failover);
    }

    #[test]
    fn nodes_replace_legacy_url() {
        let mut cfg = sample_cfg();
        cfg.url = "https://legacy.invalid".into();
        cfg.nodes = vec![RegistryNodeConfig {
            region: "Northern Europe".into(),
            node_id: Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into()),
            url: "https://oslo.invalid".into(),
        }];
        let r = resolve_registry(None, Some(&cfg), None).unwrap();
        assert_eq!(r.endpoints.len(), 1);
        assert_eq!(r.endpoints[0].url, "https://oslo.invalid");
        assert_eq!(r.endpoints[0].region.as_deref(), Some("Northern Europe"));
    }

    #[test]
    fn failover_off_uses_first_only() {
        let mut cfg = sample_cfg();
        cfg.failover = false;
        cfg.nodes = vec![
            RegistryNodeConfig {
                region: "A".into(),
                node_id: None,
                url: "https://a.invalid".into(),
            },
            RegistryNodeConfig {
                region: "B".into(),
                node_id: None,
                url: "https://b.invalid".into(),
            },
        ];
        let r = resolve_registry(None, Some(&cfg), None).unwrap();
        assert_eq!(r.endpoints.len(), 2);
        assert!(!r.failover);
    }

    #[test]
    fn enabled_false_errors() {
        let mut cfg = sample_cfg();
        cfg.enabled = false;
        assert!(resolve_registry(None, Some(&cfg), None).is_err());
    }

    #[test]
    fn max_nodes_enforced() {
        let mut cfg = sample_cfg();
        cfg.nodes = (0..MAX_REGISTRY_NODES + 1)
            .map(|i| RegistryNodeConfig {
                region: format!("R{i}"),
                node_id: None,
                url: format!("https://n{i}.invalid"),
            })
            .collect();
        assert!(endpoints_from_config(&cfg).is_err());
    }

    #[test]
    fn gateway_statuses_failover() {
        assert!(should_failover_after_http(503, true));
        assert!(!should_failover_after_http(503, false));
        assert!(!should_failover_after_http(404, true));
    }
}
