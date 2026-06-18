//! `galdra keyserver push` — upload an OpenPGP public key certificate to an HTTP registry.

use super::client::{registry_http_client, push_url, PushResponse};
use crate::commands::keyserver::client::resolve_registry_url;
use clap::Parser;
use galdra_core_host::config::RegistryKeyserverConfig;
use galdra_core_host::device::{Device, KeyFormat};
use galdra_core_host::GaldraError;
use sequoia_openpgp::armor;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Serialize as PgpSerialize;
use sequoia_openpgp::Cert;
use serde::Serialize as SerdeSerialize;
use std::collections::BTreeSet;
use std::path::PathBuf;

const DMR_ID_MAX: u32 = 16_777_215;

#[derive(Parser)]
#[command(
    name = "push",
    about = "Export the token public certificate and POST it to the registry"
)]
pub struct PushArgs {
    #[arg(long = "keyserver-url")]
    keyserver_url: Option<String>,
    /// Token slot to export (`galdra key export` semantics).
    #[arg(long, default_value_t = 1)]
    slot: u32,
    #[arg(short = 'e', long)]
    email: Option<String>,
    #[arg(long)]
    first_name: Option<String>,
    #[arg(long)]
    last_name: Option<String>,
    #[arg(short = 'c', long)]
    callsign: Option<String>,
    #[arg(long = "dmr-id")]
    dmr_id: Option<u32>,
    #[arg(long = "radio-affiliation")]
    radio_affiliation: Option<String>,
    #[arg(long = "fluxer-id")]
    fluxer_id: Option<String>,
    #[arg(long = "discord-id")]
    discord_id: Option<String>,
    #[arg(long = "irc-id")]
    irc_id: Option<String>,
    #[arg(long)]
    street: Option<String>,
    #[arg(long)]
    country: Option<String>,
    #[arg(long = "postal-code")]
    postal_code: Option<String>,
    #[arg(long)]
    region: Option<String>,
    /// Print JSON body and skip the network request.
    #[arg(long)]
    dry_run: bool,
    /// Read an armoured public key file instead of the token (requires `--dry-run`).
    #[arg(long = "fixture-armored-key")]
    fixture_armored_key: Option<PathBuf>,
}

#[derive(Debug, SerdeSerialize)]
struct PushPayload<'a> {
    email: &'a str,
    armored_public_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    callsign: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dmr_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    radio_affiliation: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fluxer_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discord_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    irc_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    street: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    postal_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<&'a str>,
}

/// Collect RFC 5322 normalised emails from certificate user IDs (deduplicated, sorted).
pub fn cert_emails_sorted(cert: &Cert) -> Vec<String> {
    let set: BTreeSet<String> = cert
        .userids()
        .filter_map(|uids| uids.email_normalized().ok().flatten())
        .collect();
    set.into_iter().collect()
}

pub fn validate_dmr_id_range(id: Option<u32>) -> Result<(), GaldraError> {
    if let Some(n) = id {
        if n == 0 || n > DMR_ID_MAX {
            return Err(GaldraError::Config(format!(
                "DMR ID must be between 1 and {DMR_ID_MAX} inclusive — got {n}"
            )));
        }
    }
    Ok(())
}

pub fn resolve_email_for_push(cert: &Cert, email_flag: Option<&str>) -> Result<String, GaldraError> {
    let emails = cert_emails_sorted(cert);
    match emails.len() {
        0 => Err(GaldraError::Config(
            "Certificate has no email User ID. Use --email.".to_string(),
        )),
        1 => {
            let only = emails[0].clone();
            match email_flag {
                None => Ok(only),
                Some(given) => {
                    let g = given.trim();
                    if g.is_empty() {
                        return Ok(only);
                    }
                    if emails.iter().any(|e| e.eq_ignore_ascii_case(g)) {
                        Ok(only)
                    } else {
                        Err(GaldraError::Config(format!(
                            "The given --email is not present on the certificate (certificate has {})",
                            only
                        )))
                    }
                }
            }
        }
        _ => {
            match email_flag {
                None => Err(GaldraError::Config(format!(
                    "Certificate has multiple email User IDs — pass --email to choose one: {}",
                    emails.join(", ")
                ))),
                Some(given) => {
                    let g = given.trim();
                    if g.is_empty() {
                        Err(GaldraError::Config(format!(
                            "Certificate has multiple email User IDs — pass --email to choose one: {}",
                            emails.join(", ")
                        )))
                    } else if emails.iter().any(|e| e.eq_ignore_ascii_case(g)) {
                        Ok(g.to_string())
                    } else {
                        Err(GaldraError::Config(format!(
                            "--email {g} is not present on the certificate; options: {}",
                            emails.join(", ")
                        )))
                    }
                }
            }
        }
    }
}

fn cert_to_armored(cert: &Cert) -> Result<String, GaldraError> {
    let mut buf = Vec::new();
    let mut w = armor::Writer::new(&mut buf, armor::Kind::PublicKey)
        .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
    cert.serialize(&mut w)
        .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
    w.finalize()
        .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
    String::from_utf8(buf).map_err(|e| GaldraError::OpenPgp(e.to_string()))
}

fn load_cert_and_armor(
    args: &PushArgs,
) -> Result<(Cert, String), GaldraError> {
    if args.dry_run {
        if let Some(ref p) = args.fixture_armored_key {
            let text = std::fs::read_to_string(p).map_err(GaldraError::Io)?;
            let cert = Cert::from_bytes(text.as_bytes())
                .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
            return Ok((cert, text));
        }
    } else if args.fixture_armored_key.is_some() {
        return Err(GaldraError::Config(
            "--fixture-armored-key is only valid with --dry-run".to_string(),
        ));
    }

    match Device::connect() {
        Ok(dev) => {
            let bytes = dev.key_export_public(args.slot, KeyFormat::Pgp)?;
            let cert = Cert::from_bytes(&bytes).map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
            let armored = if bytes.starts_with(b"-----BEGIN") {
                String::from_utf8(bytes).map_err(|e| GaldraError::OpenPgp(e.to_string()))?
            } else {
                cert_to_armored(&cert)?
            };
            Ok((cert, armored))
        }
        Err(GaldraError::DeviceNotConnected) if args.dry_run => Err(GaldraError::Config(
            "no token connected — for a dry-run without hardware, pass --fixture-armored-key \
             pointing at an armoured public key file"
                .to_string(),
        )),
        Err(e) => Err(e),
    }
}

pub fn run_push(
    args: PushArgs,
    registry_cfg: Option<&RegistryKeyserverConfig>,
    quiet: bool,
) -> Result<(), GaldraError> {
    validate_dmr_id_range(args.dmr_id)?;

    let base = resolve_registry_url(args.keyserver_url.as_deref(), registry_cfg)?;
    let _ = super::client::trimmed_registry_base(&base)?;

    let (cert, armored) = load_cert_and_armor(&args)?;
    let email = resolve_email_for_push(&cert, args.email.as_deref())?;

    if !args.dry_run && !quiet {
        println!("Using email: {email}");
    }

    let payload = PushPayload {
        email: email.as_str(),
        armored_public_key: armored.trim(),
        first_name: args.first_name.as_deref(),
        last_name: args.last_name.as_deref(),
        callsign: args.callsign.as_deref(),
        dmr_id: args.dmr_id,
        radio_affiliation: args.radio_affiliation.as_deref(),
        fluxer_id: args.fluxer_id.as_deref(),
        discord_id: args.discord_id.as_deref(),
        irc_id: args.irc_id.as_deref(),
        street: args.street.as_deref(),
        country: args.country.as_deref(),
        postal_code: args.postal_code.as_deref(),
        region: args.region.as_deref(),
    };

    let json = serde_json::to_string_pretty(&payload)
        .map_err(|e| GaldraError::Serialise(e.to_string()))?;

    if args.dry_run {
        println!("{json}");
        return Ok(());
    }

    let url = push_url(&base)?;
    let client = registry_http_client()?;
    let resp = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json)
        .send()
        .map_err(|e| {
            tracing::debug!(error = %e, "registry push request failed");
            GaldraError::Config(
                "could not reach the registry — check the URL and network connectivity".to_string(),
            )
        })?;

    let status = resp.status();
    let body_text = resp.text().map_err(|e| {
        tracing::debug!(error = %e, "registry push read body failed");
        GaldraError::Config("registry returned a response that could not be read".to_string())
    })?;
    tracing::debug!(%status, body = %body_text, "registry push response");

    if status.is_success() {
        let pr: PushResponse = serde_json::from_str(&body_text).map_err(|e| {
            tracing::debug!(error = %e, body = %body_text, "registry push JSON parse failed");
            GaldraError::Config(
                "registry returned success but the response was not valid JSON".to_string(),
            )
        })?;
        match pr.status.as_str() {
            "accepted" => {
                if let Some(fp) = pr.fingerprint {
                    println!("{fp}");
                } else {
                    println!("accepted");
                }
                Ok(())
            }
            "pending_confirmation" => {
                let msg = pr
                    .message
                    .unwrap_or_else(|| "pending confirmation".to_string());
                println!("{msg}");
                Ok(())
            }
            "error" => {
                let reason = pr
                    .reason
                    .unwrap_or_else(|| "registry rejected the request".to_string());
                Err(GaldraError::Config(format!(
                    "registry rejected the key upload: {reason}"
                )))
            }
            other => Err(GaldraError::Config(format!(
                "registry returned an unexpected status field: {other}"
            ))),
        }
    } else if status.as_u16() == 422 {
        let reason_msg = serde_json::from_str::<PushResponse>(&body_text)
            .ok()
            .filter(|pr| pr.status == "error")
            .and_then(|pr| pr.reason)
            .unwrap_or_else(|| "registry rejected the request (HTTP 422)".to_string());
        Err(GaldraError::Config(format!(
            "registry rejected the key upload: {reason_msg}"
        )))
    } else {
        Err(GaldraError::Config(format!(
            "registry returned HTTP {}; try again or contact the registry operator",
            status.as_u16(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::cert::prelude::CertBuilder;

    fn cert_with_emails(emails: &[&str]) -> Cert {
        assert!(!emails.is_empty(), "use cert_without_mail for zero-email certs");
        let mut b = CertBuilder::new();
        for e in emails {
            b = b.add_userid(format!("Test <{e}>"));
        }
        let (cert, _) = b.add_signing_subkey().generate().unwrap();
        cert
    }

    fn cert_without_mail() -> Cert {
        let (cert, _) = CertBuilder::new()
            .add_userid("Someone Without Angle Brackets")
            .add_signing_subkey()
            .generate()
            .unwrap();
        cert
    }

    #[test]
    fn email_derivation_zero() {
        let cert = cert_without_mail();
        assert!(resolve_email_for_push(&cert, None).is_err());
    }

    #[test]
    fn email_derivation_one() {
        let cert = cert_with_emails(&["a@example.com"]);
        assert_eq!(
            resolve_email_for_push(&cert, None).unwrap(),
            "a@example.com"
        );
    }

    #[test]
    fn email_derivation_many_without_flag() {
        let cert = cert_with_emails(&["a@example.com", "b@example.com"]);
        assert!(resolve_email_for_push(&cert, None).is_err());
    }

    #[test]
    fn email_derivation_many_with_flag() {
        let cert = cert_with_emails(&["a@example.com", "b@example.com"]);
        assert_eq!(
            resolve_email_for_push(&cert, Some("b@example.com")).unwrap(),
            "b@example.com"
        );
        assert!(resolve_email_for_push(&cert, Some("c@example.com")).is_err());
    }

    #[test]
    fn dmr_id_validation() {
        assert!(validate_dmr_id_range(None).is_ok());
        assert!(validate_dmr_id_range(Some(1)).is_ok());
        assert!(validate_dmr_id_range(Some(DMR_ID_MAX)).is_ok());
        assert!(validate_dmr_id_range(Some(0)).is_err());
        assert!(validate_dmr_id_range(Some(DMR_ID_MAX + 1)).is_err());
    }
}
