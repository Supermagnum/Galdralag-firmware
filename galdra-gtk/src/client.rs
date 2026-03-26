//! Blocking HTTP client for the local `galdrad` REST API.

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct GaldradClient {
    base: String,
    http: reqwest::blocking::Client,
}

impl GaldradClient {
    pub fn new(base: impl Into<String>) -> Result<Self, reqwest::Error> {
        let base = base.into().trim_end_matches('/').to_string();
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        Ok(Self { base, http })
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    fn get_text(&self, path: &str) -> Result<String, String> {
        let url = format!("{}{}", self.base, path);
        let r = self.http.get(&url).send().map_err(|e| e.to_string())?;
        if !r.status().is_success() {
            return Err(format!("{}: HTTP {}", url, r.status()));
        }
        r.text().map_err(|e| e.to_string())
    }

    pub fn health_pretty(&self) -> Result<String, String> {
        let s = self.get_text("/health")?;
        pretty_json(&s)
    }

    pub fn device_status_pretty(&self) -> Result<String, String> {
        let s = self.get_text("/device/status")?;
        pretty_json(&s)
    }

    pub fn contacts(&self) -> Result<Vec<IdentityRow>, String> {
        let s = self.get_text("/contacts")?;
        serde_json::from_str(&s).map_err(|e| format!("JSON: {e}"))
    }

    pub fn groups(&self) -> Result<Vec<GroupRow>, String> {
        let s = self.get_text("/groups")?;
        serde_json::from_str(&s).map_err(|e| format!("JSON: {e}"))
    }

    pub fn audit_pretty(&self) -> Result<String, String> {
        let s = self.get_text("/audit")?;
        pretty_json(&s)
    }
}

fn pretty_json(raw: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityRow {
    pub id: String,
    pub display_name: String,
    pub callsign: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GroupRow {
    pub name: String,
    pub member_count: usize,
}
