//! Galdra command-line interface (Phase 1: device, contacts, groups, audit, sync stub).

mod common;
mod crypto_cmds;
mod epk_cmds;
mod profile_cmds;
mod qr;
mod shamir_cmds;

use clap::{Parser, Subcommand};
use common::{
    exit_code, flush_stderr, load_app_config, open_database, print_expiry_warnings, print_json,
    prompt_pin, resolve_identity, OutputMode,
};
use galdra_core_host::audit::{self, AuditAction, AuditEntry, AuditFilter, AuditVerifyResult};
use galdra_core_host::contacts::{
    self, ContactFilter, ContactUpdate, KeySource, NewContact,
};
use galdra_core_host::device::{Device, KeyFormat, ProvisionPolicy};
use galdra_core_host::groups::{self, GroupWithMembers};
use galdra_core_host::keyserver;
use galdra_core_host::ldap;
use galdra_core_host::sync;
use galdra_core_host::GaldraError;
use galdra_core_host::SyncImportMode;
use std::io::Write;
use std::path::PathBuf;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Serialize;
use std::process::ExitCode;

/// Galdra manages contacts, groups, and Galdralag tokens.
#[derive(Parser)]
#[command(name = "galdra", version, about)]
struct Cli {
    /// Machine-readable JSON on stdout for supported commands (`json`; default is human text).
    #[arg(long = "emit", global = true, value_name = "FORMAT")]
    emit: Option<String>,
    /// Suppress informational messages (errors still print).
    #[arg(long, global = true)]
    quiet: bool,
    /// Override configuration file path.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Override SQLite database path.
    #[arg(long, global = true)]
    db: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Token presence, lock state, and firmware details.
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// Token key slot operations.
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Local contact directory.
    Contact {
        #[command(subcommand)]
        cmd: ContactCmd,
    },
    /// Named recipient groups.
    Group {
        #[command(subcommand)]
        cmd: GroupCmd,
    },
    /// Offline database import/export (Phase 3 wires the implementation).
    Sync {
        #[command(subcommand)]
        cmd: SyncCmd,
    },
    /// Append-only operation log.
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// Cipher profile registry (built-in and user-defined).
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
    /// Shamir share export and recovery (requires unlocked token when implemented).
    Shamir {
        #[command(subcommand)]
        cmd: ShamirCmd,
    },
    /// Ephemeral key offer lifecycle (generate, import, status, expire).
    Epk {
        #[command(subcommand)]
        cmd: EpkCmd,
    },
    /// Encrypt a file to a group or explicit contacts (OpenPGP or age).
    Encrypt {
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
        #[arg(long = "age-recipient")]
        age_recipient: Vec<String>,
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        to: Vec<String>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        hidden_recipient: bool,
        #[arg(long)]
        sign: bool,
        #[arg(long)]
        profile: Option<String>,
        /// 64 hex chars: CESS `K_outer` (32 bytes) from ECDH + HKDF; requires `--cess-nonce-hex`.
        #[arg(long = "cess-k-outer-hex", value_name = "HEX")]
        cess_k_outer_hex: Option<String>,
        /// 24 hex chars: 12-byte ChaCha nonce for CESS Mode A outer (must match encrypt).
        #[arg(long = "cess-nonce-hex", value_name = "HEX")]
        cess_nonce_hex: Option<String>,
    },
    /// Decrypt an OpenPGP or age message.
    Decrypt {
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
        #[arg(long = "age-identity")]
        age_identity: Option<PathBuf>,
        #[arg(long)]
        recipient: Option<String>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        profile: Option<String>,
        /// 64 hex chars: CESS `K_outer` when the inner payload is Mode A wrapped (before GALDRACP).
        #[arg(long = "cess-k-outer-hex", value_name = "HEX")]
        cess_k_outer_hex: Option<String>,
    },
    /// Sign a file (token integration pending).
    Sign {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        detach: bool,
    },
    /// Verify an OpenPGP signature.
    Verify {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        sig: Option<PathBuf>,
        #[arg(long)]
        signer: Option<String>,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// Show token connection and lock state.
    Status,
    /// Unlock the token (PIN prompt).
    Unlock,
    /// Lock the token.
    Lock,
    /// Initialise a blank token.
    Provision {
        #[arg(long)]
        pin_attempts: Option<u8>,
        #[arg(long)]
        min_pin_length: Option<u8>,
    },
    /// Permanently erase the token.
    Zeroise {
        #[arg(long)]
        confirm: bool,
    },
    /// Show firmware and slot summary.
    Info,
}

#[derive(Subcommand)]
enum KeyCmd {
    /// List key slots.
    List,
    /// Generate a new key on the token (Phase 2 integrates crypto policy).
    Generate {
        #[arg(long)]
        r#type: String,
    },
    /// Import a private key into a slot.
    Import {
        #[arg(long)]
        slot: u32,
        #[arg(long)]
        file: PathBuf,
    },
    /// Export a public key from a slot.
    Export {
        #[arg(long)]
        slot: u32,
        #[arg(long)]
        format: Option<String>,
    },
    /// Delete a key from a slot.
    Delete {
        #[arg(long)]
        slot: u32,
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
enum ContactCmd {
    /// Add a contact without a key.
    Add {
        identifier: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        callsign: Option<String>,
        #[arg(long)]
        badge: Option<String>,
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        role: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Fetch a key from a remote source.
    Fetch {
        query: String,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        server: Option<String>,
    },
    /// Import a key from a file.
    Import {
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        qr: Option<PathBuf>,
        #[arg(long)]
        peer: bool,
    },
    /// Show one contact.
    Show {
        identifier: String,
    },
    /// List contacts.
    List {
        #[arg(long)]
        expired: bool,
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        role: Option<String>,
    },
    /// Update contact metadata.
    Edit {
        identifier: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        callsign: Option<String>,
        #[arg(long)]
        badge: Option<String>,
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        role: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Delete a contact.
    Delete {
        identifier: String,
        #[arg(long)]
        confirm: bool,
    },
    /// Refresh keys from their original sources.
    Refresh {
        #[arg(long)]
        all: bool,
        identifier: Option<String>,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    Create {
        name: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        hidden_recipients: bool,
    },
    Add {
        group: String,
        #[arg(required = true)]
        identifiers: Vec<String>,
        #[arg(long)]
        expires: Option<String>,
        #[arg(long)]
        from_group: Option<String>,
    },
    Remove {
        group: String,
        #[arg(required = true)]
        identifiers: Vec<String>,
    },
    List,
    Show {
        group: String,
        #[arg(long)]
        include_expired: bool,
    },
    Edit {
        group: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        hidden_recipients: Option<String>,
    },
    Delete {
        group: String,
        #[arg(long)]
        confirm: bool,
    },
    Export {
        group: String,
        #[arg(long)]
        sign: bool,
        #[arg(long)]
        output: PathBuf,
    },
    Import {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        verify: bool,
    },
}

#[derive(Subcommand)]
enum SyncCmd {
    Export {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        sign: bool,
    },
    Import {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        verify: bool,
        #[arg(long)]
        merge: bool,
        #[arg(long)]
        replace: bool,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    Show {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        limit: Option<u64>,
    },
    Export {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        format: String,
        #[arg(long)]
        output: PathBuf,
    },
    Verify,
}

#[derive(Subcommand)]
pub enum ProfileCmd {
    /// List all profiles (built-in and user-defined).
    List,
    /// Show details for one profile.
    Show {
        name: String,
    },
    /// Add a user-defined profile.
    Add {
        name: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        curve: String,
        #[arg(long = "layer")]
        layer: Vec<String>,
        #[arg(long)]
        shamir_threshold: Option<u8>,
        #[arg(long)]
        shamir_total: Option<u8>,
    },
    /// Remove a user-defined profile.
    Remove {
        name: String,
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
pub enum ShamirCmd {
    /// Split a long-term key into Shamir shares.
    Split {
        #[arg(long)]
        slot: u32,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Recover a key from share files.
    Recover {
        #[arg(long)]
        slot: u32,
        #[arg(long = "share")]
        share: Vec<PathBuf>,
        #[arg(long)]
        confirm: bool,
    },
    /// Show metadata of a share file (no secret value).
    ShowShare {
        #[arg(long)]
        input: PathBuf,
    },
    /// Write a share as a QR code PNG image.
    ExportQr {
        #[arg(long)]
        share: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Read a share from a QR code image.
    ImportQr {
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum EpkCmd {
    /// Generate a BrainpoolP256r1 ephemeral key offer and write a .epk.gpg file.
    Generate {
        /// GnuPG key ID or fingerprint used to sign and identify the offer.
        #[arg(long)]
        gpg_key_id: String,
        /// GnuPG key IDs or fingerprints that can decrypt the offer (repeat for multiple).
        #[arg(long = "recipient", required = true)]
        recipient: Vec<String>,
        /// Offer lifetime in seconds from now.
        #[arg(long, default_value = "86400")]
        expires: i64,
        /// Output path for the .epk.gpg file.
        #[arg(long)]
        output: PathBuf,
        /// Optional operator label for the audit log.
        #[arg(long)]
        operator: Option<String>,
    },
    /// Import and validate a peer's .epk.gpg offer.
    Import {
        /// Path to the .epk.gpg file.
        input: PathBuf,
        /// Expected GnuPG fingerprint of the offer issuer (hex, spaces optional).
        #[arg(long)]
        verify_fingerprint: String,
        /// Optional operator label for the audit log.
        #[arg(long)]
        operator: Option<String>,
    },
    /// List stored ephemeral key offers.
    Status,
    /// Immediately revoke an offer and zero its private key (manual expiry).
    Expire {
        /// Session ID of the offer to revoke.
        session_id: String,
        /// Confirm the destructive operation.
        #[arg(long)]
        confirm: bool,
    },
}

fn parse_audit_action(s: &str) -> Result<AuditAction, GaldraError> {
    match s.to_ascii_lowercase().as_str() {
        "device_unlock" => Ok(AuditAction::DeviceUnlock),
        "device_lock" => Ok(AuditAction::DeviceLock),
        "device_zeroise" => Ok(AuditAction::DeviceZeroise),
        "key_import" => Ok(AuditAction::KeyImport),
        "key_delete" => Ok(AuditAction::KeyDelete),
        "key_fetch" => Ok(AuditAction::KeyFetch),
        "group_create" => Ok(AuditAction::GroupCreate),
        "group_add_member" => Ok(AuditAction::GroupAddMember),
        "group_remove_member" => Ok(AuditAction::GroupRemoveMember),
        "group_delete" => Ok(AuditAction::GroupDelete),
        "encrypt" => Ok(AuditAction::Encrypt),
        "decrypt" => Ok(AuditAction::Decrypt),
        "sign" => Ok(AuditAction::Sign),
        "verify" => Ok(AuditAction::Verify),
        "sync_export" => Ok(AuditAction::SyncExport),
        "sync_import" => Ok(AuditAction::SyncImport),
        "config_change" => Ok(AuditAction::ConfigChange),
        "epk_generate" => Ok(AuditAction::EpkGenerate),
        "epk_import" => Ok(AuditAction::EpkImport),
        "epk_derive" => Ok(AuditAction::EpkDerive),
        "epk_reject" => Ok(AuditAction::EpkReject),
        _ => Err(GaldraError::Config(format!("unknown audit action: {s}"))),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let output_mode = match cli.emit.as_deref() {
        None | Some("human") => OutputMode::Human,
        Some("json") => OutputMode::Json,
        Some(other) => {
            eprintln!("Unknown --emit mode: {}", other);
            return ExitCode::from(1);
        }
    };

    match run(cli, output_mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}", e);
            ExitCode::from(exit_code(&e) as u8)
        }
    }
}

fn run(cli: Cli, output_mode: OutputMode) -> Result<(), GaldraError> {
    let quiet = cli.quiet;
    let config = load_app_config(cli.config.as_deref())?;
    let mut db = open_database(&config, cli.db.as_deref())?;
    print_expiry_warnings(&db, &config, quiet)?;

    match cli.command {
        Commands::Device { cmd } => run_device(cmd, output_mode, quiet, &mut db),
        Commands::Key { cmd } => run_key(cmd, output_mode, quiet, &mut db),
        Commands::Contact { cmd } => run_contact(cmd, output_mode, quiet, &config, &mut db),
        Commands::Group { cmd } => run_group(cmd, output_mode, quiet, &mut db),
        Commands::Sync { cmd } => run_sync(cmd, output_mode, quiet, &mut db),
        Commands::Audit { cmd } => run_audit(cmd, output_mode, quiet, &mut db),
        Commands::Profile { cmd } => profile_cmds::run_profile(cmd, output_mode, quiet, &mut db),
        Commands::Shamir { cmd } => shamir_cmds::run_shamir(cmd, output_mode, quiet, &mut db),
        Commands::Epk { cmd } => epk_cmds::run_epk(cmd, output_mode, quiet, &mut db),
        Commands::Encrypt {
            format,
            age_recipient,
            group,
            to,
            input,
            output,
            strict,
            hidden_recipient,
            sign,
            profile,
            cess_k_outer_hex,
            cess_nonce_hex,
        } => crypto_cmds::run_encrypt(
            &mut db,
            output_mode,
            quiet,
            format,
            age_recipient,
            group,
            to,
            input,
            output,
            strict,
            hidden_recipient,
            sign,
            profile,
            cess_k_outer_hex,
            cess_nonce_hex,
        ),
        Commands::Decrypt {
            format,
            age_identity,
            recipient,
            input,
            output,
            profile,
            cess_k_outer_hex,
        } => crypto_cmds::run_decrypt(
            &mut db,
            output_mode,
            quiet,
            format,
            age_identity,
            recipient,
            input,
            output,
            profile,
            cess_k_outer_hex,
        ),
        Commands::Sign {
            input,
            output,
            detach,
        } => crypto_cmds::run_sign(&mut db, output_mode, quiet, input, output, detach),
        Commands::Verify {
            input,
            sig,
            signer,
        } => crypto_cmds::run_verify(&mut db, output_mode, quiet, input, sig, signer),
    }
}

fn run_device(
    cmd: DeviceCmd,
    output_mode: OutputMode,
    quiet: bool,
    db: &mut galdra_core_host::db::Db,
) -> Result<(), GaldraError> {
    match cmd {
        DeviceCmd::Status => {
            let dev = match Device::connect() {
                Ok(d) => Some(d),
                Err(GaldraError::DeviceNotConnected) => None,
                Err(e) => return Err(e),
            };
            if let Some(d) = dev {
                let st = d.status()?;
                let info = d.info()?;
                let serial = d.serial();
                if output_mode == OutputMode::Json {
                    print_json(&serde_json::json!({
                        "token": "connected",
                        "locked": st.locked,
                        "serial": serial,
                        "firmware": info.firmware_version,
                        "key_slots_used": info.key_slots_used,
                        "key_slot_count": info.key_slot_count,
                    }))?;
                } else {
                    println!("Token:      Connected");
                    println!(
                        "State:      {}",
                        if st.locked { "Locked" } else { "Unlocked" }
                    );
                    println!(
                        "Serial:     {}",
                        serial.as_deref().unwrap_or("(not available)")
                    );
                    println!("Firmware:   {}", info.firmware_version);
                    println!(
                        "Key slots:  {} / {} used",
                        info.key_slots_used, info.key_slot_count
                    );
                }
            } else if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({
                    "token": "disconnected",
                }))?;
            } else {
                println!("Token:      Not connected");
                if !quiet {
                    eprintln!("No Galdralag token detected.");
                }
            }
            Ok(())
        }
        DeviceCmd::Unlock => {
            let pin = prompt_pin("PIN: ")?;
            let dev = Device::connect()?;
            dev.unlock(&pin)?;
            audit::audit_append(
                db,
                AuditEntry {
                    timestamp: chrono::Utc::now(),
                    operator: None,
                    action: AuditAction::DeviceUnlock,
                    subject: None,
                    detail: None,
                    device_serial: dev.serial(),
                },
            )?;
            if !quiet {
                eprintln!("Token unlocked.");
            }
            Ok(())
        }
        DeviceCmd::Lock => {
            let dev = Device::connect()?;
            dev.lock()?;
            audit::audit_append(
                db,
                AuditEntry {
                    timestamp: chrono::Utc::now(),
                    operator: None,
                    action: AuditAction::DeviceLock,
                    subject: None,
                    detail: None,
                    device_serial: dev.serial(),
                },
            )?;
            if !quiet {
                eprintln!("Token locked.");
            }
            Ok(())
        }
        DeviceCmd::Provision {
            pin_attempts,
            min_pin_length,
        } => {
            let policy = ProvisionPolicy {
                pin_attempts: pin_attempts.unwrap_or(3),
                min_pin_length: min_pin_length.unwrap_or(5),
            };
            policy.validate()?;
            let pin = prompt_pin("New PIN: ")?;
            let dev = Device::connect()?;
            dev.provision(&pin, policy)?;
            if !quiet {
                eprintln!("Provisioning complete.");
            }
            Ok(())
        }
        DeviceCmd::Zeroise { confirm } => {
            if !confirm {
                eprintln!("This operation is irreversible. Run with --confirm to proceed.");
                return Err(GaldraError::Config("missing --confirm".to_string()));
            }
            let dev = Device::connect()?;
            confirm_zeroise(&dev)?;
            audit::audit_append(
                db,
                AuditEntry {
                    timestamp: chrono::Utc::now(),
                    operator: None,
                    action: AuditAction::DeviceZeroise,
                    subject: None,
                    detail: None,
                    device_serial: dev.serial(),
                },
            )?;
            dev.zeroise()?;
            if !quiet {
                eprintln!("Zeroise complete.");
            }
            Ok(())
        }
        DeviceCmd::Info => {
            let dev = Device::connect()?;
            let info = dev.info()?;
            if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({
                    "serial": info.serial,
                    "firmware_version": info.firmware_version,
                    "key_slot_count": info.key_slot_count,
                    "key_slots_used": info.key_slots_used,
                }))?;
            } else {
                println!(
                    "Serial:     {}",
                    info.serial.as_deref().unwrap_or("(not available)")
                );
                println!("Firmware:   {}", info.firmware_version);
                println!("Key slots:  {} / {} used", info.key_slots_used, info.key_slot_count);
            }
            Ok(())
        }
    }
}

fn confirm_zeroise(device: &Device) -> Result<(), GaldraError> {
    eprintln!();
    eprintln!("WARNING: This will permanently erase ALL key material on");
    eprintln!("         the token. This operation cannot be undone.");
    eprintln!("         Recovery requires your Shamir backup shares.");
    eprintln!();

    match device.serial() {
        Some(serial) => {
            eprintln!("Device serial: {}", serial);
            eprint!("Type the serial number exactly to confirm: ");
            flush_stderr()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).map_err(GaldraError::Io)?;
            if input.trim() != serial.as_str() {
                eprintln!("Confirmation did not match. Aborting.");
                return Err(GaldraError::UserAborted);
            }
        }
        None => {
            eprint!("Type ZEROISE (all capitals) to confirm: ");
            flush_stderr()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).map_err(GaldraError::Io)?;
            if input.trim() != "ZEROISE" {
                eprintln!("Confirmation did not match. Aborting.");
                return Err(GaldraError::UserAborted);
            }
        }
    }
    Ok(())
}

fn confirm_delete(label: &str) -> Result<(), GaldraError> {
    eprint!(
        "Delete {}? This cannot be undone. Type yes to confirm: ",
        label
    );
    flush_stderr()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).map_err(GaldraError::Io)?;
    if input.trim() != "yes" {
        eprintln!("Aborting.");
        return Err(GaldraError::UserAborted);
    }
    Ok(())
}

fn run_key(
    cmd: KeyCmd,
    output_mode: OutputMode,
    _quiet: bool,
    _db: &mut galdra_core_host::db::Db,
) -> Result<(), GaldraError> {
    let dev = Device::connect()?;
    match cmd {
        KeyCmd::List => {
            let rows = dev.key_list()?;
            if output_mode == OutputMode::Json {
                print_json(&rows)?;
            } else {
                for r in rows {
                    println!(
                        "slot {}  {}  {}  {}",
                        r.slot,
                        r.key_type,
                        r.fingerprint,
                        r.created_at.as_deref().unwrap_or("-")
                    );
                }
            }
            Ok(())
        }
        KeyCmd::Generate { .. } => Err(GaldraError::Config(
            "key generation requires Phase 2 device integration".to_string(),
        )),
        KeyCmd::Import { .. } => Err(GaldraError::Config(
            "key import requires Phase 2 device integration".to_string(),
        )),
        KeyCmd::Export {
            slot,
            format,
        } => {
            let fmt = match format.as_deref() {
                None | Some("pgp") => KeyFormat::Pgp,
                Some("pem") => KeyFormat::Pem,
                Some("der") => KeyFormat::Der,
                Some(x) => {
                    return Err(GaldraError::Config(format!("unknown export format: {x}")));
                }
            };
            let bytes = dev.key_export_public(slot, fmt)?;
            std::io::stdout()
                .write_all(&bytes)
                .map_err(GaldraError::Io)?;
            println!();
            Ok(())
        }
        KeyCmd::Delete { slot, confirm } => {
            if !confirm {
                eprintln!("This operation is irreversible. Run with --confirm to proceed.");
                return Err(GaldraError::Config("missing --confirm".to_string()));
            }
            confirm_delete(&format!("key in slot {slot}"))?;
            dev.key_delete(slot)?;
            Ok(())
        }
    }
}

fn parse_key_source(s: &str) -> Result<KeySource, GaldraError> {
    match s.to_ascii_lowercase().as_str() {
        "keyserver" => Ok(KeySource::Keyserver),
        "wkd" => Ok(KeySource::Wkd),
        "ldap" => Ok(KeySource::Ldap),
        "peer" => Ok(KeySource::Peer),
        "file" => Ok(KeySource::File),
        _ => Err(GaldraError::Config(format!("unknown key source: {s}"))),
    }
}

fn run_contact(
    cmd: ContactCmd,
    output_mode: OutputMode,
    quiet: bool,
    config: &galdra_core_host::config::Config,
    db: &mut galdra_core_host::db::Db,
) -> Result<(), GaldraError> {
    match cmd {
        ContactCmd::Add {
            identifier,
            name,
            email,
            callsign,
            badge,
            org,
            role,
            note,
        } => {
            let nc = NewContact {
                display_name: name.unwrap_or_else(|| identifier.clone()),
                callsign,
                email,
                badge_number: badge,
                organisation: org,
                department: None,
                role,
                note,
            };
            let id = contacts::contact_add(db, nc)?;
            audit::audit_append(
                db,
                AuditEntry {
                    timestamp: chrono::Utc::now(),
                    operator: None,
                    action: AuditAction::KeyImport,
                    subject: Some(id.id.clone()),
                    detail: Some("contact added without key".to_string()),
                    device_serial: None,
                },
            )?;
            if output_mode == OutputMode::Json {
                print_json(&id)?;
            } else if !quiet {
                println!("Added contact {}", id.id);
            }
            Ok(())
        }
        ContactCmd::Fetch {
            query,
            source,
            server,
        } => {
            let rt = tokio::runtime::Runtime::new().map_err(|e| GaldraError::Config(e.to_string()))?;
            let src = source.as_deref().unwrap_or("keyserver");
            let timeout = std::time::Duration::from_secs(config.keyservers.timeout_seconds);
            let certs = match src {
                "wkd" => {
                    let c = rt.block_on(keyserver::wkd_fetch(&query, timeout))?;
                    vec![c]
                }
                "keyserver" => {
                    let servers: Vec<String> = if let Some(s) = server {
                        vec![s]
                    } else {
                        config.keyservers.servers.clone()
                    };
                    rt.block_on(keyserver::keyserver_fetch(&query, &servers, timeout))?
                }
                "ldap" => {
                    let ldap_cfg = config.ldap.as_ref().ok_or_else(|| {
                        GaldraError::Config(
                            "LDAP fetch requires a [ldap] section in config.toml".to_string(),
                        )
                    })?;
                    rt.block_on(ldap::ldap_fetch_async(ldap_cfg, &query))?
                }
                "peer" => {
                    return Err(GaldraError::Config(
                        "peer fetch requires a connected token".to_string(),
                    ));
                }
                "file" => {
                    return Err(GaldraError::Config(
                        "use `galdra contact import --file` for file imports".to_string(),
                    ));
                }
                _ => {
                    return Err(GaldraError::Config(format!(
                        "unsupported fetch source: {src}"
                    )));
                }
            };
            let cert = certs
                .first()
                .ok_or_else(|| GaldraError::KeyFetch("no certificates returned".to_string()))?;
            let fp = cert
                .fingerprint()
                .to_string();
            let mut buf = Vec::new();
            cert.serialize(&mut buf)
                .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
            let nc = NewContact {
                display_name: query.clone(),
                callsign: None,
                email: None,
                badge_number: None,
                organisation: None,
                department: None,
                role: None,
                note: None,
            };
            let id = contacts::contact_add(db, nc)?;
            contacts::contact_upsert_key(
                db,
                &id.id,
                &buf,
                &fp,
                parse_key_source(src)?,
                None,
            )?;
            audit::audit_append(
                db,
                AuditEntry {
                    timestamp: chrono::Utc::now(),
                    operator: None,
                    action: AuditAction::KeyFetch,
                    subject: Some(id.id.clone()),
                    detail: Some(format!("source={src}")),
                    device_serial: None,
                },
            )?;
            if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({ "id": id.id, "fingerprint": fp }))?;
            } else if !quiet {
                println!("Fetched key for contact {}", id.id);
            }
            Ok(())
        }
        ContactCmd::Import { file, qr, peer } => {
            if peer {
                return Err(GaldraError::Config(
                    "peer import requires USB token support".to_string(),
                ));
            }
            let (bytes, detail_label): (Vec<u8>, String) = match (file.as_ref(), qr.as_ref()) {
                (None, None) => {
                    return Err(GaldraError::Config(
                        "specify --file or --qr for import".to_string(),
                    ));
                }
                (Some(_), Some(_)) => {
                    return Err(GaldraError::Config(
                        "specify only one of --file or --qr".to_string(),
                    ));
                }
                (Some(path), None) => (
                    std::fs::read(path).map_err(GaldraError::Io)?,
                    format!("file={}", path.display()),
                ),
                (None, Some(qr_path)) => (
                    crate::qr::decode_qr_image(qr_path)?,
                    format!("qr={}", qr_path.display()),
                ),
            };
            let name_source = qr.as_ref().or(file.as_ref());
            let display_name = name_source
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .unwrap_or("imported")
                .to_string();
            let cert = sequoia_openpgp::Cert::from_bytes(&bytes)
                .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
            let fp = cert.fingerprint().to_string();
            let nc = NewContact {
                display_name,
                callsign: None,
                email: None,
                badge_number: None,
                organisation: None,
                department: None,
                role: None,
                note: None,
            };
            let id = contacts::contact_add(db, nc)?;
            let mut buf = Vec::new();
            cert.serialize(&mut buf)
                .map_err(|e| GaldraError::OpenPgp(e.to_string()))?;
            let key_source = if qr.is_some() {
                KeySource::Manual
            } else {
                KeySource::File
            };
            contacts::contact_upsert_key(db, &id.id, &buf, &fp, key_source, None)?;
            audit::audit_append(
                db,
                AuditEntry {
                    timestamp: chrono::Utc::now(),
                    operator: None,
                    action: AuditAction::KeyImport,
                    subject: Some(id.id.clone()),
                    detail: Some(detail_label),
                    device_serial: None,
                },
            )?;
            if !quiet {
                println!("Imported contact {}", id.id);
            }
            Ok(())
        }
        ContactCmd::Show { identifier } => {
            let c = resolve_identity(db, &identifier)?;
            if output_mode == OutputMode::Json {
                print_json(&c)?;
            } else {
                println!("id:            {}", c.id);
                println!("display_name:  {}", c.display_name);
                println!("callsign:      {}", c.callsign.as_deref().unwrap_or(""));
                println!("email:         {}", c.email.as_deref().unwrap_or(""));
                println!("fingerprint:   {}", c.pgp_fingerprint.as_deref().unwrap_or(""));
                println!("source:        {:?}", c.source);
            }
            Ok(())
        }
        ContactCmd::List {
            expired,
            org,
            role,
        } => {
            let list = contacts::contact_list(
                db,
                ContactFilter {
                    expired,
                    organisation: org,
                    role,
                },
            )?;
            if output_mode == OutputMode::Json {
                print_json(&list)?;
            } else {
                for c in list {
                    println!(
                        "  {:36}  {:24}  {}",
                        c.id,
                        c.display_name,
                        c.email.as_deref().unwrap_or("")
                    );
                }
            }
            Ok(())
        }
        ContactCmd::Edit {
            identifier,
            name,
            email,
            callsign,
            badge,
            org,
            role,
            note,
        } => {
            let c = resolve_identity(db, &identifier)?;
            let u = ContactUpdate {
                display_name: name,
                callsign,
                email,
                badge_number: badge,
                organisation: org,
                department: None,
                role,
                note,
            };
            let updated = contacts::contact_update(db, &c.id, u)?;
            if output_mode == OutputMode::Json {
                print_json(&updated)?;
            } else if !quiet {
                println!("Updated {}", updated.id);
            }
            Ok(())
        }
        ContactCmd::Delete { identifier, confirm } => {
            if !confirm {
                eprintln!("This operation is irreversible. Run with --confirm to proceed.");
                return Err(GaldraError::Config("missing --confirm".to_string()));
            }
            let c = resolve_identity(db, &identifier)?;
            confirm_delete(&format!("contact {}", c.display_name))?;
            contacts::contact_delete(db, &c.id)?;
            audit::audit_append(
                db,
                AuditEntry {
                    timestamp: chrono::Utc::now(),
                    operator: None,
                    action: AuditAction::KeyDelete,
                    subject: Some(c.id.clone()),
                    detail: None,
                    device_serial: None,
                },
            )?;
            Ok(())
        }
        ContactCmd::Refresh { all, identifier } => {
            if all {
                return Err(GaldraError::Config(
                    "refresh --all is not fully implemented yet".to_string(),
                ));
            }
            let _ = identifier.ok_or_else(|| {
                GaldraError::Config("specify identifier or --all".to_string())
            })?;
            Err(GaldraError::Config(
                "contact refresh requires stored source metadata (planned)".to_string(),
            ))
        }
    }
}

fn run_group(
    cmd: GroupCmd,
    output_mode: OutputMode,
    quiet: bool,
    db: &mut galdra_core_host::db::Db,
) -> Result<(), GaldraError> {
    match cmd {
        GroupCmd::Create {
            name,
            description,
            hidden_recipients,
        } => {
            groups::group_create(db, &name, description.as_deref(), hidden_recipients)?;
            audit::audit_append(
                db,
                AuditEntry {
                    timestamp: chrono::Utc::now(),
                    operator: None,
                    action: AuditAction::GroupCreate,
                    subject: Some(name.clone()),
                    detail: None,
                    device_serial: None,
                },
            )?;
            if !quiet {
                println!("Created group {}", name);
            }
            Ok(())
        }
        GroupCmd::Add {
            group,
            identifiers,
            expires,
            from_group,
        } => {
            let exp = if let Some(s) = expires {
                Some(
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .map_err(|e| GaldraError::Config(e.to_string()))?
                        .with_timezone(&chrono::Utc),
                )
            } else {
                None
            };
            if let Some(other) = from_group {
                let n = groups::group_add_from_group(db, &group, &other, None)?;
                if !quiet {
                    println!("Added {} members from {}", n, other);
                }
                return Ok(());
            }
            for id_str in identifiers {
                let c = resolve_identity(db, &id_str)?;
                groups::group_add_member(db, &group, &c.id, None, exp)?;
                audit::audit_append(
                    db,
                    AuditEntry {
                        timestamp: chrono::Utc::now(),
                        operator: None,
                        action: AuditAction::GroupAddMember,
                        subject: Some(format!("{group}/{}", c.id)),
                        detail: None,
                        device_serial: None,
                    },
                )?;
            }
            Ok(())
        }
        GroupCmd::Remove { group, identifiers } => {
            for id_str in identifiers {
                let c = resolve_identity(db, &id_str)?;
                groups::group_remove_member(db, &group, &c.id)?;
                audit::audit_append(
                    db,
                    AuditEntry {
                        timestamp: chrono::Utc::now(),
                        operator: None,
                        action: AuditAction::GroupRemoveMember,
                        subject: Some(format!("{group}/{}", c.id)),
                        detail: None,
                        device_serial: None,
                    },
                )?;
            }
            Ok(())
        }
        GroupCmd::List => {
            let list = groups::group_list(db)?;
            if output_mode == OutputMode::Json {
                print_json(&list)?;
            } else {
                for g in list {
                    println!("  {:32}  {} members", g.name, g.member_count);
                }
            }
            Ok(())
        }
        GroupCmd::Show {
            group,
            include_expired: _,
        } => {
            let g = groups::group_get(db, &group)?;
            if output_mode == OutputMode::Json {
                print_json(&g)?;
            } else {
                print_group_human(&g);
            }
            Ok(())
        }
        GroupCmd::Edit {
            group,
            description,
            hidden_recipients,
        } => {
            let hidden = hidden_recipients
                .as_deref()
                .map(|s| match s {
                    "on" | "true" | "1" => Ok(true),
                    "off" | "false" | "0" => Ok(false),
                    _ => Err(GaldraError::Config("hidden-recipients: use on|off".to_string())),
                })
                .transpose()?;
            groups::group_edit(db, &group, description.as_deref(), hidden)?;
            Ok(())
        }
        GroupCmd::Delete { group, confirm } => {
            if !confirm {
                eprintln!("This operation is irreversible. Run with --confirm to proceed.");
                return Err(GaldraError::Config("missing --confirm".to_string()));
            }
            confirm_delete(&format!("group {}", group))?;
            groups::group_delete(db, &group)?;
            audit::audit_append(
                db,
                AuditEntry {
                    timestamp: chrono::Utc::now(),
                    operator: None,
                    action: AuditAction::GroupDelete,
                    subject: Some(group.clone()),
                    detail: None,
                    device_serial: None,
                },
            )?;
            Ok(())
        }
        GroupCmd::Export { .. } | GroupCmd::Import { .. } => Err(GaldraError::Config(
            "group export/import packages are implemented in Phase 3".to_string(),
        )),
    }
}

fn print_group_human(g: &GroupWithMembers) {
    println!("Group:       {}", g.name);
    println!(
        "Description: {}",
        g.description.as_deref().unwrap_or("")
    );
    println!("Hidden:      {}", g.hidden_recipients);
    for m in &g.members {
        let exp = m
            .expires_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "none".to_string());
        println!(
            "  - {}  expired={}  membership_expires={}",
            m.identity.display_name, m.is_expired, exp
        );
    }
}

fn run_sync(
    cmd: SyncCmd,
    output_mode: OutputMode,
    quiet: bool,
    db: &mut galdra_core_host::db::Db,
) -> Result<(), GaldraError> {
    match cmd {
        SyncCmd::Export { output, sign } => {
            if sign {
                return Err(GaldraError::Config(
                    "sync export signing requires a connected token (not yet integrated)".to_string(),
                ));
            }
            sync::sync_export(db, &output)?;
            audit::audit_append(
                db,
                AuditEntry {
                    timestamp: chrono::Utc::now(),
                    operator: None,
                    action: AuditAction::SyncExport,
                    subject: Some(output.display().to_string()),
                    detail: None,
                    device_serial: None,
                },
            )?;
            if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({ "output": output }))?;
            } else if !quiet {
                eprintln!("Exported sync package to {}.", output.display());
            }
            Ok(())
        }
        SyncCmd::Import {
            input,
            verify,
            merge,
            replace,
        } => {
            if verify && !quiet {
                eprintln!(
                    "Warning: package signature verification is not implemented; --verify ignored."
                );
            }
            if merge && replace {
                return Err(GaldraError::Config(
                    "use only one of --merge or --replace".to_string(),
                ));
            }
            let mode = if replace {
                SyncImportMode::Replace
            } else {
                SyncImportMode::Merge
            };
            sync::sync_import(db, &input, mode)?;
            audit::audit_append(
                db,
                AuditEntry {
                    timestamp: chrono::Utc::now(),
                    operator: None,
                    action: AuditAction::SyncImport,
                    subject: Some(input.display().to_string()),
                    detail: Some(format!("mode={mode:?}")),
                    device_serial: None,
                },
            )?;
            if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({ "input": input, "mode": format!("{mode:?}") }))?;
            } else if !quiet {
                eprintln!("Imported sync package from {}.", input.display());
            }
            Ok(())
        }
    }
}

fn run_audit(
    cmd: AuditCmd,
    output_mode: OutputMode,
    _quiet: bool,
    db: &mut galdra_core_host::db::Db,
) -> Result<(), GaldraError> {
    match cmd {
        AuditCmd::Show {
            since,
            action,
            limit,
        } => {
            let since_dt = if let Some(s) = since {
                Some(
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .map_err(|e| GaldraError::Config(e.to_string()))?
                        .with_timezone(&chrono::Utc),
                )
            } else {
                None
            };
                let act = if let Some(a) = action {
                    Some(parse_audit_action(&a)?)
                } else {
                    None
                };
            let rows = audit::audit_query(
                db,
                AuditFilter {
                    since: since_dt,
                    action: act,
                    limit,
                },
            )?;
            if output_mode == OutputMode::Json {
                print_json(&rows)?;
            } else {
                for r in rows {
                    let subj = r.subject.as_deref().unwrap_or("");
                    let det = r.detail.as_deref().unwrap_or("");
                    if let Some(d) = r.detail.as_deref() {
                        if d.contains('\n') {
                            println!(
                                "{}  {}  {}",
                                r.timestamp.to_rfc3339(),
                                r.action.as_str(),
                                subj
                            );
                            for line in d.lines() {
                                println!("  {line}");
                            }
                            continue;
                        }
                    }
                    println!(
                        "{}  {}  {}  {}",
                        r.timestamp.to_rfc3339(),
                        r.action.as_str(),
                        subj,
                        det
                    );
                }
            }
            Ok(())
        }
        AuditCmd::Export {
            since,
            format,
            output,
        } => {
            let since_dt = if let Some(s) = since {
                Some(
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .map_err(|e| GaldraError::Config(e.to_string()))?
                        .with_timezone(&chrono::Utc),
                )
            } else {
                None
            };
            let filter = AuditFilter {
                since: since_dt,
                action: None,
                limit: None,
            };
            let mut f = std::fs::File::create(&output).map_err(GaldraError::Io)?;
            match format.as_str() {
                "csv" => audit::audit_export_csv(db, filter, &mut f)?,
                "json" => audit::audit_export_json(db, filter, &mut f)?,
                _ => return Err(GaldraError::Config("format must be csv or json".to_string())),
            }
            Ok(())
        }
        AuditCmd::Verify => {
            let v = audit::audit_verify_chain(db)?;
            if output_mode == OutputMode::Json {
                print_json(&v)?;
            } else {
                match v {
                    AuditVerifyResult::Ok => println!("audit chain OK"),
                    AuditVerifyResult::ChainBroken {
                        entry_id,
                        expected_hash,
                        actual_hash,
                    } => {
                        return Err(GaldraError::AuditChainBroken(format!(
                            "entry {entry_id}: expected {expected_hash} got {actual_hash}"
                        )));
                    }
                }
            }
            Ok(())
        }
    }
}
