//! OpenPGP encrypt / decrypt / sign / verify CLI wiring.

use crate::identity_cmds;
use galdra_core_host::audit::{self, AuditAction, AuditEntry};
use galdra_core_host::cipher_envelope::{
    open_plaintext_from_openpgp_literal, parse_hex_fixed, seal_plaintext_with_profile,
    wrap_inner_with_cess_mode_a,
};
use galdra_core_host::contacts::{self, ContactFilter, Identity};
use galdra_core_host::encrypt::{self, try_decrypt_session_key_from_cert};
use galdra_core_host::groups;
use galdra_core_host::openpgp_card_attrs::OpenPgpKeySlot;
use galdra_core_host::openpgp_pcsc;
use galdra_core_host::profiles::{self, ProfileStore};
use galdra_core_host::sign;
use galdra_core_host::{GaldraError, GaldraFingerprint};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sha2::digest::Digest;
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::common::{print_json, resolve_identity, OutputMode};

fn identity_to_cert(id: &Identity) -> Result<sequoia_openpgp::Cert, GaldraError> {
    let bytes = id
        .pgp_pubkey
        .as_ref()
        .ok_or_else(|| GaldraError::OpenPgp(format!("contact {} has no OpenPGP key", id.id)))?;
    sequoia_openpgp::Cert::from_bytes(bytes).map_err(|e| GaldraError::OpenPgp(e.to_string()))
}

fn collect_recipient_identities(
    db: &galdra_core_host::db::Db,
    group: Option<String>,
    to: Vec<String>,
) -> Result<Vec<Identity>, GaldraError> {
    if let Some(gname) = group {
        if !to.is_empty() {
            return Err(GaldraError::Config(
                "use either --group or --to, not both".to_string(),
            ));
        }
        return groups::group_active_members(db, &gname);
    }
    if to.is_empty() {
        return Err(GaldraError::Config(
            "specify --group or at least one --to".to_string(),
        ));
    }
    let mut out = Vec::new();
    for id_str in to {
        out.push(resolve_identity(db, &id_str)?);
    }
    Ok(out)
}

/// Placeholder sender fingerprint (hex) for profile AAD until token signing integration supplies a real value.
const PLACEHOLDER_SENDER_FP: &str = "0000000000000000000000000000000000000000";

fn session_id_from_ciphertext(ciphertext: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(ciphertext);
    let out = h.finalize();
    hex::encode(&out[..8])
}

/// Encrypt file to contacts or group members.
#[allow(clippy::too_many_arguments)]
pub fn run_encrypt(
    db: &mut galdra_core_host::db::Db,
    output_mode: OutputMode,
    quiet: bool,
    format: Option<String>,
    age_recipient: Vec<String>,
    group: Option<String>,
    to: Vec<String>,
    input: PathBuf,
    output: PathBuf,
    strict: bool,
    hidden_recipient_cli: bool,
    sign: bool,
    profile: Option<String>,
    cess_k_outer_hex: Option<String>,
    cess_nonce_hex: Option<String>,
    emit_fingerprint: bool,
) -> Result<(), GaldraError> {
    let fmt = format.as_deref().unwrap_or("openpgp");
    if fmt == "age" {
        return run_encrypt_age(db, output_mode, quiet, &age_recipient, input, output);
    }
    if fmt != "openpgp" {
        return Err(GaldraError::Config(format!(
            "unknown --format {fmt} (use openpgp or age)"
        )));
    }
    if !age_recipient.is_empty() {
        return Err(GaldraError::Config(
            "--age-recipient is only used with --format age".to_string(),
        ));
    }
    let policy = StandardPolicy::new();
    let idents = collect_recipient_identities(db, group.clone(), to)?;
    let mut certs = Vec::new();
    for id in &idents {
        certs.push(identity_to_cert(id)?);
    }

    let hidden = if let Some(ref gname) = group {
        let g = groups::group_get(db, gname)?;
        g.hidden_recipients || hidden_recipient_cli
    } else {
        hidden_recipient_cli
    };

    let plaintext = std::fs::read(&input).map_err(GaldraError::Io)?;
    let fname = input
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string());

    let store = ProfileStore::load(db)?;
    let profile_name = profile.as_deref().unwrap_or("standard").to_string();
    let cipher_profile = store
        .get_owned(&profile_name)
        .ok_or_else(|| GaldraError::ProfileNotFound(profile_name.clone()))?;

    if emit_fingerprint && cipher_profile.ephemeral_ecdh() {
        return Err(GaldraError::Config(
            identity_cmds::GALDRA_FINGERPRINT_EPHEMERAL_ECDH_BLOCKED.to_string(),
        ));
    }

    let galdra_fp: Option<GaldraFingerprint> = if cipher_profile.ephemeral_ecdh() {
        None
    } else {
        openpgp_pcsc::preflight_openpgp_slot_via_pcsc(OpenPgpKeySlot::Sig)?;
        let pk = openpgp_pcsc::read_sig_public_key_bytes_via_pcsc()?;
        Some(GaldraFingerprint::from_public_key_bytes(&pk))
    };

    let sender_fp = galdra_fp
        .as_ref()
        .map(|f| f.canonical().to_string())
        .unwrap_or_else(|| PLACEHOLDER_SENDER_FP.to_string());

    let cess_k_outer: Option<[u8; 32]> = match (&cess_k_outer_hex, &cess_nonce_hex) {
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => {
            return Err(GaldraError::Config(
                "CESS Mode A requires both --cess-k-outer-hex and --cess-nonce-hex (12-byte nonce)"
                    .to_string(),
            ));
        }
        (Some(kh), Some(nh)) => {
            let k = parse_hex_fixed::<32>("--cess-k-outer-hex", kh)?;
            let _ = parse_hex_fixed::<12>("--cess-nonce-hex", nh)?;
            Some(k)
        }
    };

    let ciphertext = if sign {
        return Err(GaldraError::Config(
            "cleartext signing during encrypt requires a connected token (not yet integrated)"
                .to_string(),
        ));
    } else {
        let mut sealed =
            seal_plaintext_with_profile(&cipher_profile, &plaintext, sender_fp.as_str())?;
        if let Some(ref k_outer) = cess_k_outer {
            let nonce = parse_hex_fixed::<12>(
                "--cess-nonce-hex",
                cess_nonce_hex.as_ref().expect("paired with k_outer"),
            )?;
            sealed = wrap_inner_with_cess_mode_a(&sealed, cipher_profile.name(), k_outer, &nonce)?;
        }
        encrypt::encrypt_openpgp(&policy, &sealed, fname.as_deref(), &certs, hidden, strict)?
    };

    std::fs::write(&output, &ciphertext).map_err(GaldraError::Io)?;

    let sid = session_id_from_ciphertext(&ciphertext);
    let detail = profiles::audit_crypto_detail_multiline(&cipher_profile, idents.len(), &sid);
    audit::audit_append(
        db,
        AuditEntry {
            timestamp: chrono::Utc::now(),
            operator: None,
            action: AuditAction::Encrypt,
            subject: group.map(|g| format!("group:{g}")),
            detail: Some(detail),
            device_serial: None,
        },
    )?;

    if output_mode == OutputMode::Json {
        let mut v = serde_json::json!({
            "output": output,
            "bytes": ciphertext.len(),
            "recipients": idents.len(),
            "profile": profile_name,
            "cess_mode_a": cess_k_outer.is_some(),
        });
        if emit_fingerprint {
            if let Some(ref fp) = galdra_fp {
                v["galdra_fingerprint_canonical"] = serde_json::Value::String(fp.canonical().to_string());
                v["galdra_fingerprint_display"] = serde_json::Value::String(fp.display());
            }
        }
        print_json(&v)?;
    } else if !quiet {
        eprintln!(
            "Wrote {} bytes for {} recipient(s) (profile {}{}).",
            ciphertext.len(),
            idents.len(),
            cipher_profile.name(),
            if cess_k_outer.is_some() {
                ", CESS Mode A outer"
            } else {
                ""
            },
        );
        if emit_fingerprint {
            if let Some(fp) = galdra_fp {
                eprintln!("Galdralag fingerprint (G:): {}", fp.display());
            }
        }
    }
    Ok(())
}

fn run_encrypt_age(
    db: &mut galdra_core_host::db::Db,
    output_mode: OutputMode,
    quiet: bool,
    age_recipient: &[String],
    input: PathBuf,
    output: PathBuf,
) -> Result<(), GaldraError> {
    if age_recipient.is_empty() {
        return Err(GaldraError::Config(
            "age encryption requires at least one --age-recipient (age1...)".to_string(),
        ));
    }
    let mut recipients: Vec<Box<dyn age::Recipient + Send>> = Vec::new();
    for s in age_recipient {
        let r: age::x25519::Recipient = s
            .parse()
            .map_err(|e| GaldraError::Config(format!("invalid --age-recipient: {e}")))?;
        recipients.push(Box::new(r));
    }
    let plaintext = std::fs::read(&input).map_err(GaldraError::Io)?;
    let encryptor = age::Encryptor::with_recipients(recipients).ok_or_else(|| {
        GaldraError::Config("age encryption requires at least one valid recipient".to_string())
    })?;
    let mut ciphertext = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .map_err(|e| GaldraError::Config(format!("{e}")))?;
        writer
            .write_all(&plaintext)
            .map_err(|e| GaldraError::Config(format!("{e}")))?;
        writer
            .finish()
            .map_err(|e| GaldraError::Config(format!("{e}")))?;
    }
    std::fs::write(&output, &ciphertext).map_err(GaldraError::Io)?;

    audit::audit_append(
        db,
        AuditEntry {
            timestamp: chrono::Utc::now(),
            operator: None,
            action: AuditAction::Encrypt,
            subject: None,
            detail: Some(format!("format=age,bytes={}", ciphertext.len())),
            device_serial: None,
        },
    )?;

    if output_mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "output": output,
            "bytes": ciphertext.len(),
            "format": "age",
        }))?;
    } else if !quiet {
        eprintln!(
            "Wrote {} bytes (age) for {} recipient(s).",
            ciphertext.len(),
            age_recipient.len()
        );
    }
    Ok(())
}

/// Decrypt ciphertext (requires token integration for production keys).
#[allow(clippy::too_many_arguments)]
pub fn run_decrypt(
    db: &mut galdra_core_host::db::Db,
    output_mode: OutputMode,
    quiet: bool,
    format: Option<String>,
    age_identity: Option<PathBuf>,
    recipient: Option<String>,
    input: PathBuf,
    output: PathBuf,
    profile_hint: Option<String>,
    cess_k_outer_hex: Option<String>,
) -> Result<(), GaldraError> {
    let fmt = format.as_deref().unwrap_or("openpgp");
    if fmt == "age" {
        return run_decrypt_age(db, output_mode, quiet, age_identity, input, output);
    }
    if fmt != "openpgp" {
        return Err(GaldraError::Config(format!(
            "unknown --format {fmt} (use openpgp or age)"
        )));
    }
    let recipient = recipient.ok_or_else(|| {
        GaldraError::Config("decrypt (OpenPGP) requires a recipient contact identifier".to_string())
    })?;
    if age_identity.is_some() {
        return Err(GaldraError::Config(
            "--age-identity is only used with --format age".to_string(),
        ));
    }
    let policy = StandardPolicy::new();
    let id = resolve_identity(db, &recipient)?;
    let cert = identity_to_cert(&id)?;
    let ciphertext = std::fs::read(&input).map_err(GaldraError::Io)?;

    let try_decrypt =
        |pkesk: &sequoia_openpgp::packet::PKESK,
         sym: Option<sequoia_openpgp::types::SymmetricAlgorithm>| {
            try_decrypt_session_key_from_cert(&policy, &cert, pkesk, sym)
        };

    let inner = encrypt::decrypt_openpgp(&policy, &ciphertext, &cert, try_decrypt, &[])
        .map_err(|e| {
            if matches!(e, GaldraError::OpenPgp(_)) {
                GaldraError::Config(
                    "decryption failed — host stores public keys only; use a connected token with decryption support (integration pending)".to_string(),
                )
            } else {
                e
            }
        })?;

    let cess_k_outer: Option<[u8; 32]> = match cess_k_outer_hex.as_ref() {
        None => None,
        Some(s) => Some(parse_hex_fixed::<32>("--cess-k-outer-hex", s)?),
    };

    let store = ProfileStore::load(db)?;
    let (plain, pname) = match open_plaintext_from_openpgp_literal(
        &inner,
        cess_k_outer.as_ref(),
        |n| store.get_owned(n),
    ) {
        Ok(pair) => {
            if let Some(ref hint) = profile_hint {
                if hint != &pair.1 {
                    eprintln!(
                        "Warning: --profile {hint} does not match ciphertext profile name {}.",
                        pair.1
                    );
                }
            }
            pair
        }
        Err(GaldraError::ProfileNotFound(name)) => {
            eprintln!(
                "Warning: ciphertext was encrypted with profile \"{}\" which is not in the local registry. Add the profile definition before decrypting.",
                name
            );
            return Err(GaldraError::ProfileNotFound(name));
        }
        Err(e) => return Err(e),
    };

    if pname == "legacy-openpgp" && profile_hint.is_some() {
        eprintln!(
            "Warning: --profile is ignored for messages without a Galdra cipher-profile inner envelope."
        );
    }

    std::fs::write(&output, &plain).map_err(GaldraError::Io)?;

    let sid = session_id_from_ciphertext(&ciphertext);
    let detail = if let Some(p) = store.get(&pname) {
        profiles::audit_crypto_detail_multiline(p, 1, &sid)
    } else {
        format!("profile:{pname}\nsession_id:{sid} (profile definition missing from registry)")
    };

    audit::audit_append(
        db,
        AuditEntry {
            timestamp: chrono::Utc::now(),
            operator: None,
            action: AuditAction::Decrypt,
            subject: Some(id.id.clone()),
            detail: Some(detail),
            device_serial: None,
        },
    )?;

    if output_mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "output": output,
            "bytes": plain.len(),
            "profile": pname,
        }))?;
    } else if !quiet {
        eprintln!(
            "Wrote {} bytes of plaintext (profile {}).",
            plain.len(),
            pname
        );
    }
    Ok(())
}

fn run_decrypt_age(
    db: &mut galdra_core_host::db::Db,
    output_mode: OutputMode,
    quiet: bool,
    age_identity: Option<PathBuf>,
    input: PathBuf,
    output: PathBuf,
) -> Result<(), GaldraError> {
    let id_path = age_identity.ok_or_else(|| {
        GaldraError::Config(
            "age decryption requires --age-identity PATH to an age identity file".to_string(),
        )
    })?;
    let ciphertext = std::fs::read(&input).map_err(GaldraError::Io)?;
    let decryptor = match age::Decryptor::new(&ciphertext[..])
        .map_err(|e| GaldraError::Config(e.to_string()))?
    {
        age::Decryptor::Recipients(d) => d,
        age::Decryptor::Passphrase(_) => {
            return Err(GaldraError::Config(
                "age file uses passphrase encryption; decrypt with the age tool".to_string(),
            ));
        }
    };
    let idf =
        age::IdentityFile::from_file(id_path.display().to_string()).map_err(GaldraError::Io)?;
    let identities: Vec<age::x25519::Identity> = idf
        .into_identities()
        .into_iter()
        .map(|e| {
            let age::IdentityFileEntry::Native(i) = e;
            i
        })
        .collect();
    if identities.is_empty() {
        return Err(GaldraError::Config(
            "no native age identities found in identity file".to_string(),
        ));
    }
    let mut r = decryptor
        .decrypt(identities.iter().map(|i| i as &dyn age::Identity))
        .map_err(|e| GaldraError::Config(e.to_string()))?;
    let mut plaintext = Vec::new();
    r.read_to_end(&mut plaintext)
        .map_err(|e| GaldraError::Config(e.to_string()))?;
    std::fs::write(&output, &plaintext).map_err(GaldraError::Io)?;

    audit::audit_append(
        db,
        AuditEntry {
            timestamp: chrono::Utc::now(),
            operator: None,
            action: AuditAction::Decrypt,
            subject: None,
            detail: Some(format!("format=age,bytes={}", plaintext.len())),
            device_serial: None,
        },
    )?;

    if output_mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "output": output,
            "bytes": plaintext.len(),
            "format": "age",
        }))?;
    } else if !quiet {
        eprintln!("Wrote {} bytes of plaintext (age).", plaintext.len());
    }
    Ok(())
}

/// Detached-sign a file (token integration pending).
pub fn run_sign(
    _db: &mut galdra_core_host::db::Db,
    _output_mode: OutputMode,
    _quiet: bool,
    _input: PathBuf,
    _output: PathBuf,
    _detach: bool,
) -> Result<(), GaldraError> {
    Err(GaldraError::Config(
        "signing requires a connected token with signing key material (not yet integrated)"
            .to_string(),
    ))
}

fn verification_pool(
    db: &galdra_core_host::db::Db,
    signer: Option<String>,
) -> Result<Vec<sequoia_openpgp::Cert>, GaldraError> {
    if let Some(s) = signer {
        let id = resolve_identity(db, &s)?;
        return Ok(vec![identity_to_cert(&id)?]);
    }
    let list = contacts::contact_list(
        db,
        ContactFilter {
            expired: false,
            organisation: None,
            role: None,
        },
    )?;
    let mut certs = Vec::new();
    for id in list {
        if id.pgp_pubkey.is_some() {
            certs.push(identity_to_cert(&id)?);
        }
    }
    if certs.is_empty() {
        return Err(GaldraError::OpenPgp(
            "no contacts with public keys for verification".to_string(),
        ));
    }
    Ok(certs)
}

/// Verify a detached or cleartext signature.
pub fn run_verify(
    db: &mut galdra_core_host::db::Db,
    output_mode: OutputMode,
    quiet: bool,
    input: PathBuf,
    sig: Option<PathBuf>,
    signer: Option<String>,
) -> Result<(), GaldraError> {
    let policy = StandardPolicy::new();
    let pool = verification_pool(db, signer)?;

    if let Some(sig_path) = sig {
        let data = std::fs::read(&input).map_err(GaldraError::Io)?;
        let sig_bytes = std::fs::read(&sig_path).map_err(GaldraError::Io)?;
        sign::verify_openpgp_detached(&policy, &sig_bytes, &data, &pool)?;
    } else {
        return Err(GaldraError::Config(
            "inline-signed message verification is not wired yet; use --sig for detached signatures"
                .to_string(),
        ));
    }

    audit::audit_append(
        db,
        AuditEntry {
            timestamp: chrono::Utc::now(),
            operator: None,
            action: AuditAction::Verify,
            subject: Some(input.display().to_string()),
            detail: None,
            device_serial: None,
        },
    )?;

    if output_mode == OutputMode::Json {
        print_json(&serde_json::json!({ "ok": true }))?;
    } else if !quiet {
        println!("Good signature.");
    }
    Ok(())
}
