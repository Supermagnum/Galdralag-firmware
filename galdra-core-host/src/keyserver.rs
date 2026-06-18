//! HKP keyserver and WKD fetch helpers.

use crate::GaldraError;
use sequoia_net::KeyServer;
use sequoia_net::reqwest::Client;
use sequoia_net::wkd;
use sequoia_openpgp::Cert;
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::parse::Parse;
use std::time::Duration;

fn reject_plain_http(url: &str) -> Result<(), GaldraError> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("hkp://") {
        return Err(GaldraError::Config(
            "plain HTTP keyserver URLs are not permitted; use hkps://".to_string(),
        ));
    }
    Ok(())
}

fn userid_from_query(query: &str) -> Result<UserID, GaldraError> {
    if query.contains('@') {
        UserID::from_address(None, None, query).map_err(|e| GaldraError::KeyFetch(e.to_string()))
    } else {
        UserID::from_bytes(query.as_bytes()).map_err(|e| GaldraError::KeyFetch(e.to_string()))
    }
}

fn flatten_certs<E: std::fmt::Display>(results: Vec<Result<Cert, E>>) -> Result<Vec<Cert>, GaldraError> {
    let mut out = Vec::new();
    for r in results {
        let cert = r.map_err(|e| GaldraError::KeyFetch(e.to_string()))?;
        out.push(cert);
    }
    Ok(out)
}

/// Search HKP keyservers in order; returns the first successful non-empty result.
pub async fn keyserver_fetch(
    query: &str,
    servers: &[String],
    timeout: Duration,
) -> Result<Vec<Cert>, GaldraError> {
    if servers.is_empty() {
        return Err(GaldraError::KeyFetch("no keyservers configured".to_string()));
    }
    let mut last_err = String::from("no successful keyserver response");
    let uid = userid_from_query(query)?;
    for server in servers {
        reject_plain_http(server)?;
        let ks = KeyServer::new(server).map_err(|e| GaldraError::KeyFetch(e.to_string()))?;
        let attempt = tokio::time::timeout(timeout, ks.search(uid.clone())).await;
        match attempt {
            Ok(Ok(results)) => {
                let certs = flatten_certs(results)?;
                if !certs.is_empty() {
                    return Ok(certs);
                }
                last_err = "empty search result".to_string();
            }
            Ok(Err(e)) => last_err = e.to_string(),
            Err(_) => last_err = "keyserver request timed out".to_string(),
        }
    }
    Err(GaldraError::KeyFetch(last_err))
}

/// Fetch a single certificate via WKD for an email address.
pub async fn wkd_fetch(email: &str, timeout: Duration) -> Result<Cert, GaldraError> {
    let client = Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| GaldraError::KeyFetch(e.to_string()))?;
    let attempt = tokio::time::timeout(timeout, wkd::get(&client, email)).await;
    let results = match attempt {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(GaldraError::KeyFetch(e.to_string())),
        Err(_) => return Err(GaldraError::KeyFetch("WKD request timed out".to_string())),
    };
    let certs = flatten_certs(results)?;
    certs
        .into_iter()
        .next()
        .ok_or_else(|| GaldraError::KeyFetch("WKD returned no certificates".to_string()))
}
