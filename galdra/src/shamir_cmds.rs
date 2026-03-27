//! `galdra shamir` subcommands.

use galdra_core_host::device::Device;
use galdra_core_host::profiles::ProfileStore;
use galdra_core_host::shamir_ops::{shamir_recover_key, shamir_split_key, ShamirShareExport};
use galdra_core_host::GaldraError;
use image::{ImageBuffer, Luma};
use qrcode::QrCode;
use std::io::Write;

use crate::common::{print_json, OutputMode};
use crate::qr;

pub fn run_shamir(
    cmd: crate::ShamirCmd,
    output_mode: OutputMode,
    quiet: bool,
    db: &mut galdra_core_host::db::Db,
) -> Result<(), GaldraError> {
    match cmd {
        crate::ShamirCmd::Split {
            slot,
            profile,
            output_dir,
        } => {
            let store = ProfileStore::load(db)?;
            let p = store
                .get_owned(&profile)
                .ok_or_else(|| GaldraError::ProfileNotFound(profile.clone()))?;
            let dev = Device::connect()?;
            let shares = shamir_split_key(&dev, &p, slot)?;
            std::fs::create_dir_all(&output_dir).map_err(GaldraError::Io)?;
            let n = shares.len();
            for sh in shares {
                let idx = sh.index;
                let path = output_dir.join(format!("share-{idx}-of-{n}.galdra-share"));
                let arm = sh.to_armoured();
                std::fs::write(&path, arm.as_bytes()).map_err(GaldraError::Io)?;
            }
            if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({ "shares": n, "dir": output_dir }))?;
            } else if !quiet {
                eprintln!(
                    "Generated {n} shares. Distribute them to trusted parties. Keep this device and the shares separate."
                );
            }
            Ok(())
        }
        crate::ShamirCmd::Recover {
            slot,
            share,
            confirm,
        } => {
            if share.is_empty() {
                return Err(GaldraError::Config(
                    "specify at least one --share file".to_string(),
                ));
            }
            if !confirm {
                return Err(GaldraError::Config(
                    "add --confirm to import a recovered key into this slot (may overwrite)".to_string(),
                ));
            }
            let mut exports = Vec::new();
            for path in &share {
                let text = std::fs::read_to_string(path).map_err(GaldraError::Io)?;
                exports.push(ShamirShareExport::from_armoured(&text)?);
            }
            let dev = Device::connect()?;
            shamir_recover_key(&dev, &exports, slot)?;
            if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({ "ok": true, "slot": slot }))?;
            } else if !quiet {
                eprintln!("Imported recovered key material into slot {slot}.");
            }
            Ok(())
        }
        crate::ShamirCmd::ShowShare { input } => {
            let text = std::fs::read_to_string(&input).map_err(GaldraError::Io)?;
            let ex = ShamirShareExport::from_armoured(&text)?;
            let total = ex.total;
            let idx = ex.index;
            if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({
                    "profile": ex.profile_name,
                    "index": idx,
                    "total": total,
                    "fingerprint": ex.fingerprint,
                    "created": ex.created_at_rfc3339,
                }))?;
            } else if !quiet {
                println!("Profile: {}", ex.profile_name);
                println!("Share index: {idx} of {total}");
                println!("Key fingerprint: {}", ex.fingerprint);
                println!("Created: {}", ex.created_at_rfc3339);
            }
            Ok(())
        }
        crate::ShamirCmd::ExportQr { share, output } => {
            let text = std::fs::read_to_string(&share).map_err(GaldraError::Io)?;
            let arm = text.trim();
            let code = QrCode::new(arm).map_err(|e| GaldraError::Config(format!("QR: {e}")))?;
            let img = code.render::<Luma<u8>>().build();
            let w = img.width();
            let h = img.height();
            let mut buf = ImageBuffer::new(w, h);
            for (x, y, p) in img.enumerate_pixels() {
                buf.put_pixel(x, y, *p);
            }
            buf.save(&output)
                .map_err(|e| GaldraError::Config(format!("image save: {e}")))?;
            if !quiet {
                eprintln!("Wrote QR image to {}.", output.display());
            }
            Ok(())
        }
        crate::ShamirCmd::ImportQr { input } => {
            let payload = qr::decode_qr_image(&input)?;
            let text = String::from_utf8(payload).map_err(|e| GaldraError::Config(e.to_string()))?;
            let ex = ShamirShareExport::from_armoured(&text)?;
            if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({
                    "profile": ex.profile_name,
                    "index": ex.index,
                    "total": ex.total,
                    "fingerprint": ex.fingerprint,
                }))?;
            } else if !quiet {
                println!("Profile: {}", ex.profile_name);
                println!("Share index: {} of {}", ex.index, ex.total);
                println!("Key fingerprint: {}", ex.fingerprint);
                eprint!("Save armoured share to file path (press Enter to skip): ");
                std::io::stderr().flush().map_err(GaldraError::Io)?;
                let mut line = String::new();
                std::io::stdin()
                    .read_line(&mut line)
                    .map_err(GaldraError::Io)?;
                let path = line.trim();
                if !path.is_empty() {
                    let arm = ex.to_armoured();
                    std::fs::write(path, arm.as_bytes()).map_err(GaldraError::Io)?;
                    eprintln!("Wrote {}.", path);
                }
            }
            Ok(())
        }
    }
}
