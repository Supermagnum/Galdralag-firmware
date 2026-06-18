//! `galdra profile` subcommands.

use galdra_core_host::cipher_profile::CipherProfileError;
use galdra_core_host::profiles::{
    build_profile_from_options, parse_curve_wire, parse_layer_name, ProfileStore,
};
use galdra_core_host::GaldraError;
use std::io::Write;

use crate::common::{print_json, OutputMode};

fn map_cipher(e: CipherProfileError) -> GaldraError {
    GaldraError::CipherProfile(format!("{e:?}"))
}

pub fn run_profile(
    cmd: crate::ProfileCmd,
    output_mode: OutputMode,
    quiet: bool,
    db: &mut galdra_core_host::db::Db,
) -> Result<(), GaldraError> {
    match cmd {
        crate::ProfileCmd::List => {
            let store = ProfileStore::load(db)?;
            let rows = store.list();
            if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({ "profiles": rows }))?;
            } else if !quiet {
                println!(
                    "{:<22} {:<10} {:<18} {:<40} {:<10} {:<10}",
                    "name", "ecdhe", "curve", "layers", "shamir", "source"
                );
                for r in rows {
                    let layers = r.layers.join(", ");
                    let sham = if r.shamir_n > 1 {
                        format!("{}/{}", r.shamir_k, r.shamir_n)
                    } else {
                        "none".to_string()
                    };
                    let src = if r.is_builtin { "builtin" } else { "user" };
                    let ecdhe = if r.ephemeral_ecdh { "on" } else { "off" };
                    println!(
                        "{:<22} {:<10} {:<18} {:<40} {:<10} {:<10}",
                        r.name, ecdhe, r.curve, layers, sham, src
                    );
                }
            }
            Ok(())
        }
        crate::ProfileCmd::Show { name } => {
            let store = ProfileStore::load(db)?;
            let p = store
                .get(&name)
                .ok_or_else(|| GaldraError::ProfileNotFound(name.clone()))?;
            use galdra_core_host::cipher_profile::{curve_audit_str, layer_audit_name};
            let mut layer_lines = String::new();
            for (i, layer) in p.layers().iter().enumerate() {
                let label = if i == 0 {
                    "inner"
                } else if i + 1 == p.layers().len() {
                    "outer AEAD"
                } else {
                    "middle"
                };
                layer_lines.push_str(&format!(
                    "                   {}. {} ({})\n",
                    i + 1,
                    layer_audit_name(*layer),
                    label
                ));
            }
            let sham = p.shamir();
            let sham_s = if sham.is_active() {
                format!("{}-of-{}", sham.threshold, sham.total)
            } else {
                "none".to_string()
            };
            let src = if store.is_builtin(&name) {
                "built-in"
            } else {
                "user-defined"
            };
            if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({
                    "name": p.name(),
                    "description": p.description(),
                    "curve": curve_audit_str(p.curve()),
                    "layers": p.layers().iter().map(|l| layer_audit_name(*l)).collect::<Vec<_>>(),
                    "shamir": sham_s,
                    "ephemeral_ecdh": p.ephemeral_ecdh(),
                    "source": src,
                }))?;
            } else if !quiet {
                println!("Name:        {}", p.name());
                println!("Description: {}", p.description());
                println!("Curve:       {}", curve_audit_str(p.curve()));
                println!(
                    "Ephemeral ECDH (profile): {}",
                    if p.ephemeral_ecdh() { "on" } else { "off" }
                );
                print!("Layers:\n{}", layer_lines);
                println!("Shamir:      {}", sham_s);
                println!("Source:      {}", src);
            }
            Ok(())
        }
        crate::ProfileCmd::Add {
            name,
            description,
            curve,
            layer,
            shamir_threshold,
            shamir_total,
            no_ephemeral_ecdh,
        } => {
            if layer.is_empty() {
                return Err(GaldraError::Config(
                    "specify at least one --layer".to_string(),
                ));
            }
            let mut layers = Vec::new();
            for s in &layer {
                let l = parse_layer_name(s)?;
                if layers.contains(&l) {
                    return Err(map_cipher(CipherProfileError::DuplicateCipher));
                }
                layers.push(l);
            }
            if layers.len() > 4 {
                return Err(GaldraError::Config(
                    "at most 4 --layer entries allowed".to_string(),
                ));
            }
            let curve_p = parse_curve_wire(&curve)?;
            let kt = shamir_threshold.unwrap_or(1);
            let nt = shamir_total.unwrap_or(1);
            let ephemeral_ecdh = !no_ephemeral_ecdh;
            let profile = build_profile_from_options(
                &name,
                description.as_deref().unwrap_or(""),
                curve_p,
                &layers,
                kt,
                nt,
                ephemeral_ecdh,
            )?;
            if output_mode == OutputMode::Json {
                let mut store = ProfileStore::load(db)?;
                store.add(db, profile)?;
                print_json(&serde_json::json!({ "ok": true, "name": name }))?;
                return Ok(());
            }
            if !quiet {
                eprintln!(
                    "Profile: {}\nCurve: {:?}\nLayers: {:?}\nShamir: {}/{}\nEphemeral ECDH: {}",
                    name,
                    curve_p,
                    layers,
                    kt,
                    nt,
                    if ephemeral_ecdh { "on" } else { "off" }
                );
                eprint!("Save this profile? [y/N]: ");
                std::io::stderr().flush().map_err(GaldraError::Io)?;
                let mut line = String::new();
                std::io::stdin()
                    .read_line(&mut line)
                    .map_err(GaldraError::Io)?;
                if !line.trim().eq_ignore_ascii_case("y") {
                    return Err(GaldraError::UserAborted);
                }
            }
            let mut store = ProfileStore::load(db)?;
            store.add(db, profile)?;
            if !quiet {
                eprintln!("Saved profile \"{}\".", name);
            }
            Ok(())
        }
        crate::ProfileCmd::Remove { name, confirm } => {
            let store = ProfileStore::load(db)?;
            if store.is_builtin(&name) {
                return Err(GaldraError::Config(
                    "built-in profiles cannot be removed".to_string(),
                ));
            }
            if !confirm {
                return Err(GaldraError::Config(
                    "add --confirm to remove this profile".to_string(),
                ));
            }
            let mut store = store;
            store.remove(db, &name)?;
            if output_mode == OutputMode::Json {
                print_json(&serde_json::json!({ "removed": name }))?;
            } else if !quiet {
                eprintln!("Removed profile \"{}\".", name);
            }
            Ok(())
        }
    }
}
