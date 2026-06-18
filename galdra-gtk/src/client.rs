//! Blocking HTTP client for the local `galdrad` REST API.

use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct GaldradClient {
    base: String,
    http: reqwest::blocking::Client,
}

impl GaldradClient {
    pub fn new(base: impl Into<String>) -> Result<Self, reqwest::Error> {
        let base = base.into().trim_end_matches('/').to_string();
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
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

    fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<String, String> {
        let url = format!("{}{}", self.base, path);
        let r = self
            .http
            .post(&url)
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = r.status();
        let t = r.text().map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("{}: HTTP {} — {}", url, status, t));
        }
        Ok(t)
    }

    fn delete(&self, path: &str) -> Result<(), String> {
        let url = format!("{}{}", self.base, path);
        let r = self.http.delete(&url).send().map_err(|e| e.to_string())?;
        let status = r.status();
        if !status.is_success() {
            let t = r.text().unwrap_or_default();
            return Err(format!("{}: HTTP {} — {}", url, status, t));
        }
        Ok(())
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

    pub fn profiles(&self) -> Result<Vec<ProfileSummary>, String> {
        let s = self.get_text("/profiles")?;
        let v: ProfilesResponse = serde_json::from_str(&s).map_err(|e| format!("JSON: {e}"))?;
        Ok(v.profiles)
    }

    pub fn get_profile(&self, name: &str) -> Result<ProfileSummary, String> {
        let enc = urlencoding_encode(name);
        let s = self.get_text(&format!("/profiles/{enc}"))?;
        serde_json::from_str(&s).map_err(|e| format!("JSON: {e}"))
    }

    pub fn create_profile(&self, body: &CreateProfileBody) -> Result<(), String> {
        let v = serde_json::to_value(body).map_err(|e| e.to_string())?;
        self.post_json("/profiles", &v)?;
        Ok(())
    }

    pub fn delete_profile(&self, name: &str) -> Result<(), String> {
        let enc = urlencoding_encode(name);
        self.delete(&format!("/profiles/{enc}"))
    }

    pub fn shamir_split(&self, slot: u32, profile: &str) -> Result<Vec<String>, String> {
        let body = serde_json::json!({
            "slot": slot,
            "profile": profile,
        });
        let s = self.post_json("/shamir/split", &body)?;
        serde_json::from_str(&s).map_err(|e| format!("JSON: {e}"))
    }

    pub fn shamir_recover(&self, slot: u32, shares: &[String]) -> Result<(), String> {
        let body = serde_json::json!({
            "slot": slot,
            "shares": shares,
        });
        self.post_json("/shamir/recover", &body)?;
        Ok(())
    }

    pub fn shamir_share_info(&self, armoured: &str) -> Result<ShamirShareInfo, String> {
        let enc = urlencoding_encode(armoured);
        let s = self.get_text(&format!("/shamir/share-info?armoured={enc}"))?;
        serde_json::from_str(&s).map_err(|e| format!("JSON: {e}"))
    }

    pub fn post_encrypt_b64(
        &self,
        group: &str,
        profile: &str,
        plaintext: &[u8],
    ) -> Result<String, String> {
        let url = format!("{}/encrypt", self.base);
        let body = serde_json::json!({
            "group": group,
            "plaintext_b64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                plaintext,
            ),
            "profile": profile,
            "sign": false,
        });
        let r = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = r.status();
        if !status.is_success() {
            let t = r.text().unwrap_or_default();
            return Err(format!("{}: HTTP {} — {}", url, status, t));
        }
        let t = r.text().map_err(|e| e.to_string())?;
        pretty_json(&t)
    }

    pub fn post_decrypt_b64(
        &self,
        recipient: &str,
        profile_hint: Option<&str>,
        ciphertext: &[u8],
    ) -> Result<String, String> {
        let url = format!("{}/decrypt", self.base);
        let mut body = serde_json::json!({
            "recipient": recipient,
            "ciphertext_b64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                ciphertext,
            ),
        });
        if let Some(p) = profile_hint {
            body["profile"] = serde_json::Value::String(p.to_string());
        }
        let r = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = r.status();
        if !status.is_success() {
            let t = r.text().unwrap_or_default();
            return Err(format!("{}: HTTP {} — {}", url, status, t));
        }
        let t = r.text().map_err(|e| e.to_string())?;
        pretty_json(&t)
    }
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(*b))
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn pretty_json(raw: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Deserialize)]
struct ProfilesResponse {
    profiles: Vec<ProfileSummary>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProfileSummary {
    pub name: String,
    pub description: String,
    pub curve: String,
    pub layers: Vec<String>,
    pub shamir_k: u8,
    pub shamir_n: u8,
    pub is_builtin: bool,
}

impl ProfileSummary {
    pub fn layer_summary(&self) -> String {
        self.layers.join(", ")
    }

    pub fn shamir_label(&self) -> String {
        if self.shamir_k > 1 || self.shamir_n > 1 {
            format!("{}/{}", self.shamir_k, self.shamir_n)
        } else {
            "off".to_string()
        }
    }

    pub fn source_label(&self) -> &'static str {
        if self.is_builtin {
            "built-in"
        } else {
            "user"
        }
    }

    pub fn dropdown_label(&self) -> String {
        format!("{} — {}", self.name, self.layer_summary())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateProfileBody {
    pub name: String,
    pub description: Option<String>,
    pub curve: String,
    pub layers: Vec<String>,
    pub shamir_threshold: Option<u8>,
    pub shamir_total: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShamirShareInfo {
    pub profile: String,
    pub threshold: u8,
    pub total: u8,
    pub index: u8,
    pub fingerprint: String,
    pub created: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityRow {
    pub id: String,
    pub display_name: String,
    pub callsign: Option<String>,
    pub email: Option<String>,
    pub fluxer_id: Option<String>,
    pub discord_id: Option<String>,
    pub irc_id: Option<String>,
    pub dmr_id: Option<i64>,
    pub radio_affiliation: Option<String>,
    pub street: Option<String>,
    pub country: Option<String>,
    pub postal_code: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GroupRow {
    pub name: String,
    pub member_count: usize,
}
