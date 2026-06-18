//! LDAP / Active Directory key fetch using `ldap3`.

use crate::config::LdapConfig;
use crate::GaldraError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::Cert;

fn ldap_escape_filter_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\5c"),
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

fn cert_from_ldap_value(v: &[u8]) -> Result<Cert, GaldraError> {
    if let Ok(c) = Cert::from_bytes(v) {
        return Ok(c);
    }
    let s = std::str::from_utf8(v)
        .map_err(|_| GaldraError::OpenPgp("LDAP key attribute is not valid UTF-8".to_string()))?;
    let t = s.trim();
    if let Ok(c) = Cert::from_bytes(t.as_bytes()) {
        return Ok(c);
    }
    let b64: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    let decoded = STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| GaldraError::OpenPgp(format!("base64: {e}")))?;
    Cert::from_bytes(&decoded).map_err(|e| GaldraError::OpenPgp(e.to_string()))
}

/// Fetch OpenPGP certificates from LDAP using the configured filter and key attribute.
pub async fn ldap_fetch_async(cfg: &LdapConfig, query: &str) -> Result<Vec<Cert>, GaldraError> {
    let url_lower = cfg.url.to_ascii_lowercase();
    if url_lower.starts_with("ldap://") && !cfg.allow_plain_ldap {
        return Err(GaldraError::Config(
            "plain LDAP is disabled (use ldaps:// or set allow_plain_ldap = true in config)"
                .to_string(),
        ));
    }
    if url_lower.starts_with("ldap://") && cfg.allow_plain_ldap {
        eprintln!("Warning: LDAP connection without TLS (allow_plain_ldap = true).");
    }

    let password = std::env::var(&cfg.bind_pw_env).map_err(|_| {
        GaldraError::Config(format!(
            "bind password environment variable `{}` is not set",
            cfg.bind_pw_env
        ))
    })?;

    let filter = cfg
        .user_filter
        .replace("{query}", &ldap_escape_filter_value(query));

    let (conn, mut ldap) = LdapConnAsync::new(cfg.url.as_str())
        .await
        .map_err(|e| GaldraError::KeyFetch(format!("LDAP connect: {e}")))?;
    ldap3::drive!(conn);

    ldap.simple_bind(cfg.bind_dn.as_str(), password.as_str())
        .await
        .map_err(|e| GaldraError::KeyFetch(format!("LDAP bind: {e}")))?
        .success()
        .map_err(|e| GaldraError::KeyFetch(format!("LDAP bind result: {e}")))?;

    let key_attr = cfg.key_attribute.as_str();
    let (rs, _res) = ldap
        .search(
            cfg.base_dn.as_str(),
            Scope::Subtree,
            filter.as_str(),
            vec![key_attr],
        )
        .await
        .map_err(|e| GaldraError::KeyFetch(format!("LDAP search: {e}")))?
        .success()
        .map_err(|e| GaldraError::KeyFetch(format!("LDAP search result: {e}")))?;

    let mut certs = Vec::new();
    for entry in rs {
        let se = SearchEntry::construct(entry);
        for (attr, vals) in se.attrs {
            if !attr.eq_ignore_ascii_case(key_attr) {
                continue;
            }
            for v in vals {
                certs.push(cert_from_ldap_value(v.as_bytes())?);
            }
        }
    }

    if certs.is_empty() {
        return Err(GaldraError::KeyFetch(
            "no OpenPGP keys found in LDAP search results".to_string(),
        ));
    }

    Ok(certs)
}
