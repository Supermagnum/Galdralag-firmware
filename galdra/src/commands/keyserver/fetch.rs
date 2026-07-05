//! `galdra keyserver fetch` — download a registry key row by fingerprint or email.

use super::client::{
    email_lookup_url, endpoint_label, fingerprint_lookup_url, registry_http_client,
    resolve_registry, FetchKeysBody, KeyRecord,
};
use galdra_core_host::config::RegistryKeyserverConfig;
use galdra_core_host::registry;
use galdra_core_host::GaldraError;
use clap::Parser;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "fetch",
    about = "Download a published public key or metadata from the registry"
)]
pub struct FetchArgs {
    #[arg(long = "keyserver-url")]
    keyserver_url: Option<String>,
    #[arg(short = 'f', long = "fingerprint")]
    fingerprint: Option<String>,
    #[arg(short = 'e', long)]
    email: Option<String>,
    #[arg(short = 'o', long = "output", default_value = "armored")]
    output: String,
    #[arg(long)]
    save: Option<PathBuf>,
}

pub fn normalize_fingerprint_hex(raw: &str) -> Result<String, GaldraError> {
    let compact: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.len() != 40 {
        return Err(GaldraError::Config(format!(
            "Fingerprint must be exactly 40 hexadecimal characters — got {}",
            compact.len()
        )));
    }
    if !compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(GaldraError::Config(
            "Fingerprint must contain only hexadecimal digits".to_string(),
        ));
    }
    Ok(compact.to_ascii_uppercase())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FetchOutputFmt {
    Armored,
    Json,
}

fn parse_output_mode(s: &str) -> Result<FetchOutputFmt, GaldraError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "armored" => Ok(FetchOutputFmt::Armored),
        "json" => Ok(FetchOutputFmt::Json),
        other => Err(GaldraError::Config(format!(
            "unknown --output `{other}` (expected armored or json)"
        ))),
    }
}

fn flatten_records(body: FetchKeysBody) -> Vec<KeyRecord> {
    match body {
        FetchKeysBody::One(k) => vec![k],
        FetchKeysBody::Many(list) => list,
    }
}

fn write_stdout_or_file(path: Option<&PathBuf>, data: &str) -> Result<(), GaldraError> {
    if let Some(p) = path {
        std::fs::write(p, data).map_err(GaldraError::Io)?;
    } else {
        print!("{}", data);
        if !data.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct FetchJsonEnvelope<'a> {
    records: &'a [KeyRecord],
    #[serde(skip_serializing_if = "Option::is_none")]
    ambiguity_note: Option<&'static str>,
}

pub fn run_fetch(
    args: FetchArgs,
    registry_cfg: Option<&RegistryKeyserverConfig>,
    quiet: bool,
) -> Result<(), GaldraError> {
    let fp_raw = args
        .fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|x| !x.is_empty());

    let email = args.email.as_deref().map(str::trim).filter(|x| !x.is_empty());

    let fp_hex = fp_raw.map(normalize_fingerprint_hex).transpose()?;

    if let (None, None) = (fp_hex.as_ref(), email) {
        return Err(GaldraError::Config(
            "Nothing to look up — pass --fingerprint or --email.".to_string(),
        ));
    }

    let resolution = resolve_registry(args.keyserver_url.as_deref(), registry_cfg)?;
    let fmt = parse_output_mode(&args.output)?;

    let client = registry_http_client(resolution.timeout_seconds)?;
    let mut last_transport_err = String::from("no registry endpoint responded");

    let records = {
        let mut found: Option<Vec<KeyRecord>> = None;
        let endpoint_count = resolution.endpoints.len();
        for (idx, ep) in resolution.endpoints.iter().enumerate() {
            let label = endpoint_label(ep.region.as_deref(), &ep.url);
            let url = if let Some(fp_str) = fp_hex.as_ref() {
                fingerprint_lookup_url(&ep.url, fp_str)?
            } else {
                let em = email.ok_or_else(|| {
                    GaldraError::Config(
                        "internal error: resolved lookup without fingerprint or email".to_string(),
                    )
                })?;
                email_lookup_url(&ep.url, em)?
            };

            let resp = match client
                .get(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(error = %e, endpoint = %label, "registry fetch transport error");
                    last_transport_err = format!(
                        "could not reach {label} — check URL and network connectivity"
                    );
                    if resolution.failover && idx + 1 < endpoint_count {
                        if !quiet {
                            eprintln!("registry node unreachable ({label}); trying next");
                        }
                        continue;
                    }
                    return Err(GaldraError::Config(last_transport_err));
                }
            };

            let status = resp.status();
            let body_text = resp.text().map_err(|e| {
                tracing::debug!(error = %e, "registry fetch read body failed");
                GaldraError::Config("registry returned a response that could not be read".to_string())
            })?;
            tracing::debug!(%status, endpoint = %label, body = %body_text, "registry fetch response");

            if status.as_u16() == 404 {
                return Err(GaldraError::Config(
                    "No key found for the given query".to_string(),
                ));
            }
            if registry::is_registry_application_status(status.as_u16()) {
                return Err(GaldraError::Config(format!(
                    "registry returned HTTP {} from {label}",
                    status.as_u16(),
                )));
            }
            if !status.is_success() {
                if resolution.failover
                    && registry::should_failover_after_http(status.as_u16(), true)
                    && idx + 1 < endpoint_count
                {
                    if !quiet {
                        eprintln!(
                            "registry node returned HTTP {} ({label}); trying next",
                            status.as_u16()
                        );
                    }
                    last_transport_err = format!(
                        "registry returned HTTP {} from {label}",
                        status.as_u16()
                    );
                    continue;
                }
                return Err(GaldraError::Config(format!(
                    "registry returned HTTP {} from {label}",
                    status.as_u16(),
                )));
            }

            let parsed: FetchKeysBody = serde_json::from_str(&body_text).map_err(|e| {
                tracing::debug!(error = %e, body = %body_text, "registry fetch JSON parse failed");
                GaldraError::Config(
                    "registry returned success but the body was not valid JSON".to_string(),
                )
            })?;
            let batch = flatten_records(parsed);
            if batch.is_empty() {
                return Err(GaldraError::Config(
                    "No key found for the given query".to_string(),
                ));
            }
            found = Some(batch);
            break;
        }
        found.ok_or_else(|| GaldraError::Config(last_transport_err))?
    };

    let ambiguity_note: Option<&'static str> = if records.len() > 1 {
        Some("Multiple registry records matched; output includes all matching rows.")
    } else {
        None
    };
    if !quiet {
        if let Some(note) = ambiguity_note {
            eprintln!("{note}");
        }
    }

    match fmt {
        FetchOutputFmt::Armored => {
            let blob = if records.len() == 1 {
                records[0].armored_key.trim().to_string()
            } else {
                let mut accum = String::new();
                for (i, row) in records.iter().enumerate() {
                    accum.push_str(&format!("----- record {} -----", i + 1));
                    accum.push('\n');
                    accum.push_str(row.armored_key.trim());
                    accum.push('\n');
                }
                accum
            };
            let to_stdout = args.save.is_none();
            write_stdout_or_file(args.save.as_ref(), &blob)?;
            if to_stdout && !quiet {
                eprintln!("# To import: gpg --import < output.asc");
            }
            Ok(())
        }
        FetchOutputFmt::Json => {
            let env = FetchJsonEnvelope {
                records: &records,
                ambiguity_note,
            };
            let out = serde_json::to_string_pretty(&env)
                .map_err(|e| GaldraError::Serialise(e.to_string()))?;
            write_stdout_or_file(args.save.as_ref(), &out)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_normalizes() {
        assert_eq!(
            normalize_fingerprint_hex(" 0123456789abcdef0123456789abcdef01234567 ").unwrap(),
            "0123456789ABCDEF0123456789ABCDEF01234567"
        );
    }

    #[test]
    fn fingerprint_bad_length() {
        assert!(normalize_fingerprint_hex("aabbccdd").is_err());
    }

    #[test]
    fn fingerprint_bad_char() {
        assert!(normalize_fingerprint_hex("ggbbcc99112233445566778899aabbccddeeff").is_err());
    }
}
