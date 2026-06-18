//! `galdra epk` subcommands — ephemeral key offer lifecycle management.

use crate::common::{print_json, OutputMode};
use galdra_core_host::ephemeral_offers::{self, GenerateParams, ImportParams, OfferRow};
use galdra_core_host::GaldraError;
use std::path::PathBuf;

pub fn run_epk(
    cmd: crate::EpkCmd,
    output_mode: OutputMode,
    quiet: bool,
    db: &mut galdra_core_host::db::Db,
) -> Result<(), GaldraError> {
    match cmd {
        crate::EpkCmd::Generate {
            gpg_key_id,
            recipient,
            expires,
            output,
            operator,
        } => run_generate(
            db,
            output_mode,
            quiet,
            gpg_key_id,
            recipient,
            expires,
            output,
            operator,
        ),

        crate::EpkCmd::Import {
            input,
            verify_fingerprint,
            operator,
        } => run_import(db, output_mode, quiet, input, verify_fingerprint, operator),

        crate::EpkCmd::Status => run_status(db, output_mode, quiet),

        crate::EpkCmd::Expire {
            session_id,
            confirm,
        } => run_expire(db, output_mode, quiet, session_id, confirm),
    }
}

fn run_generate(
    db: &mut galdra_core_host::db::Db,
    output_mode: OutputMode,
    quiet: bool,
    gpg_key_id: String,
    recipients: Vec<String>,
    expires: i64,
    output: PathBuf,
    operator: Option<String>,
) -> Result<(), GaldraError> {
    let params = GenerateParams {
        gpg_key_id: &gpg_key_id,
        recipient_key_ids: &recipients,
        expires_in_seconds: expires,
        operator,
    };
    let (session_id, gpg_bytes) = ephemeral_offers::generate_offer(db, &params)?;
    std::fs::write(&output, &gpg_bytes).map_err(GaldraError::Io)?;
    if output_mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "session_id": session_id,
            "output": output.display().to_string(),
            "size_bytes": gpg_bytes.len(),
        }))?;
    } else if !quiet {
        println!("Ephemeral offer generated.");
        println!("  Session ID : {}", session_id);
        println!("  Written to : {}", output.display());
    }
    Ok(())
}

fn run_import(
    db: &mut galdra_core_host::db::Db,
    output_mode: OutputMode,
    quiet: bool,
    input: PathBuf,
    verify_fingerprint: String,
    operator: Option<String>,
) -> Result<(), GaldraError> {
    let bytes = std::fs::read(&input).map_err(GaldraError::Io)?;
    let params = ImportParams {
        offer_gpg_bytes: &bytes,
        verify_fingerprint: &verify_fingerprint,
        operator,
    };
    let offer = ephemeral_offers::import_offer(db, &params)?;
    if output_mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "session_id": offer.session_id,
            "epk_hex": offer.epk_hex,
            "long_term_fingerprint": offer.long_term_fingerprint,
            "expires_at": offer.expires_at,
            "created_at": offer.created_at,
        }))?;
    } else if !quiet {
        println!("Ephemeral offer imported.");
        println!("  Session ID  : {}", offer.session_id);
        println!("  Fingerprint : {}", offer.long_term_fingerprint);
        println!("  Expires at  : {}", offer.expires_at);
    }
    Ok(())
}

fn run_status(
    db: &galdra_core_host::db::Db,
    output_mode: OutputMode,
    quiet: bool,
) -> Result<(), GaldraError> {
    let rows = ephemeral_offers::list_offers(db)?;
    if output_mode == OutputMode::Json {
        let json_rows: Vec<_> = rows.iter().map(row_to_json).collect();
        print_json(&serde_json::json!({ "offers": json_rows }))?;
        return Ok(());
    }
    if rows.is_empty() {
        if !quiet {
            println!("No ephemeral offers stored.");
        }
        return Ok(());
    }
    if !quiet {
        println!(
            "{:<34} {:<18} {:<10} {:<8} {:<8} {:<5}",
            "session_id", "long_term_fp", "expires_at", "consumed", "revoked", "mine"
        );
        for r in &rows {
            let mine = if r.my_private_key_bytes.is_some() {
                "yes"
            } else {
                "no"
            };
            let consumed = if r.consumed { "yes" } else { "no" };
            let revoked = if r.revoked { "yes" } else { "no" };
            let fp_short = if r.long_term_fingerprint.len() > 16 {
                &r.long_term_fingerprint[r.long_term_fingerprint.len() - 16..]
            } else {
                &r.long_term_fingerprint
            };
            println!(
                "{:<34} ...{:<15} {:<10} {:<8} {:<8} {:<5}",
                r.session_id, fp_short, r.expires_at, consumed, revoked, mine,
            );
        }
    }
    Ok(())
}

fn run_expire(
    db: &mut galdra_core_host::db::Db,
    output_mode: OutputMode,
    quiet: bool,
    session_id: String,
    confirm: bool,
) -> Result<(), GaldraError> {
    if !confirm {
        eprintln!(
            "Pass --confirm to immediately revoke offer {} and zero its private key.",
            session_id
        );
        return Err(GaldraError::UserAborted);
    }
    ephemeral_offers::revoke_offer(db, &session_id)?;

    // Audit the revocation as a reject with reason "manual_revoke".
    use chrono::Utc;
    use galdra_core_host::audit::{audit_append, AuditAction, AuditEntry};
    audit_append(
        db,
        AuditEntry {
            timestamp: Utc::now(),
            operator: None,
            action: AuditAction::EpkReject,
            subject: Some(session_id.clone()),
            detail: Some(format!(
                r#"{{"session_id":"{}","reason":"manual_revoke"}}"#,
                session_id
            )),
            device_serial: None,
        },
    )?;

    if output_mode == OutputMode::Json {
        print_json(&serde_json::json!({ "session_id": session_id, "revoked": true }))?;
    } else if !quiet {
        println!("Offer {} revoked and private key zeroed.", session_id);
    }
    Ok(())
}

fn row_to_json(r: &OfferRow) -> serde_json::Value {
    serde_json::json!({
        "session_id": r.session_id,
        "curve": r.curve,
        "long_term_fingerprint": r.long_term_fingerprint,
        "expires_at": r.expires_at,
        "created_at": r.created_at,
        "consumed": r.consumed,
        "revoked": r.revoked,
        "has_private_key": r.my_private_key_bytes.is_some(),
        "imported_at": r.imported_at,
    })
}
