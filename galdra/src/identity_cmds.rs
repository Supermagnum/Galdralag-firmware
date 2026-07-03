//! `galdra identity` subcommands.

use galdra_core_host::openpgp_card_attrs::OpenPgpKeySlot;
use galdra_core_host::openpgp_pcsc;
use galdra_core_host::profiles::ProfileStore;
use galdra_core_host::{GaldraError, GaldraFingerprint};

use crate::common::{print_json, OutputMode};

/// User-facing error when a profile still has ephemeral ECDH enabled.
pub const GALDRA_FINGERPRINT_EPHEMERAL_ECDH_BLOCKED: &str = "Galdralag fingerprints are not available when authenticated ephemeral ECDH is active in the selected profile.";

pub fn run_identity(
    cmd: crate::IdentityCmd,
    output_mode: OutputMode,
    quiet: bool,
    db: &mut galdra_core_host::db::Db,
) -> Result<(), GaldraError> {
    match cmd {
        crate::IdentityCmd::Fingerprint { profile } => {
            let store = ProfileStore::load(db)?;
            let profile_name = profile.as_deref().unwrap_or("standard").to_string();
            let p = store
                .get_owned(&profile_name)
                .ok_or_else(|| GaldraError::ProfileNotFound(profile_name.clone()))?;
            if p.ephemeral_ecdh() {
                return Err(GaldraError::Config(
                    GALDRA_FINGERPRINT_EPHEMERAL_ECDH_BLOCKED.to_string(),
                ));
            }
            openpgp_pcsc::preflight_openpgp_slot_via_pcsc(OpenPgpKeySlot::Sig)?;
            let pk = openpgp_pcsc::read_sig_public_key_bytes_via_pcsc()?;
            let fp = GaldraFingerprint::from_public_key_bytes(&pk);
            if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({
                    "profile": profile_name,
                    "galdra_fingerprint_canonical": fp.canonical(),
                    "galdra_fingerprint_display": fp.display(),
                }))?;
            } else if !quiet {
                println!("Galdralag fingerprint (G:)");
                println!("{}", fp.display());
                println!("This fingerprint is suitable for OpenPGP Web of Trust use when ephemeral ECDH is not active.");
            }
            Ok(())
        }
    }
}
