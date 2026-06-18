// USB CDC PIN provisioning client for Galdralag first boot (operator-chosen PINs).
//
// Wire format matches xous-core `services/usb-bao1x` provisioning serial: two newline-terminated
// lines (user PIN, then admin PIN), raw bytes, no STATUS/COMMIT framing.
//
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use clap::Parser;
use serialport::{DataBits, Parity, SerialPort, StopBits};

/// Matches firmware `CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES` / provisioning personality cap.
const PROVISIONING_PIN_MAX: usize = 32;

#[derive(Parser, Debug)]
#[command(
    name = "galdralag-provision",
    about = "Provision user and admin PINs over USB CDC (xous two-line protocol; first boot)"
)]
struct Args {
    /// Serial device (e.g. /dev/ttyACM0)
    #[arg(long)]
    port: String,
    #[arg(long)]
    user_pin: Option<String>,
    #[arg(long)]
    admin_pin: Option<String>,
    /// After sending PINs, wait up to N seconds for the device to USB-reset (serial read error).
    #[arg(long, default_value = "15")]
    wait_reset_secs: u64,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("galdralag-provision: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();

    let user_pin = match args.user_pin {
        Some(s) => s,
        None => rpassword::prompt_password("User PIN: ").map_err(|e| e.to_string())?,
    };
    let admin_pin = match args.admin_pin {
        Some(s) => s,
        None => rpassword::prompt_password("Admin PIN: ").map_err(|e| e.to_string())?,
    };

    let ub = user_pin.as_bytes();
    let ab = admin_pin.as_bytes();
    if ub.is_empty() || ub.len() > PROVISIONING_PIN_MAX {
        return Err(format!("user PIN must be 1..={PROVISIONING_PIN_MAX} bytes"));
    }
    if ab.is_empty() || ab.len() > PROVISIONING_PIN_MAX {
        return Err(format!("admin PIN must be 1..={PROVISIONING_PIN_MAX} bytes"));
    }

    let mut port = serialport::new(&args.port, 115_200)
        .data_bits(DataBits::Eight)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .timeout(Duration::from_secs(3))
        .open()
        .map_err(|e| e.to_string())?;

    // Line 1: user PIN; line 2: admin PIN (matches `IrqProvSerialRx` handling in usb-bao1x).
    send_line(port.as_mut(), ub, true)?;
    send_line(port.as_mut(), ab, true)?;

    println!("Sent PIN lines. Device should store OKV1 in PDDB and reset USB for CCID enumeration.");

    wait_for_usb_reset_hint(
        port.as_mut(),
        Duration::from_secs(args.wait_reset_secs),
    )?;

    Ok(())
}

fn send_line(port: &mut dyn SerialPort, payload: &[u8], add_newline: bool) -> Result<(), String> {
    port.write_all(payload).map_err(|e| e.to_string())?;
    if add_newline {
        port.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    port.flush().map_err(|e| e.to_string())?;
    Ok(())
}

/// Optional confirmation: after firmware saves PDDB it forces a USB reset; reads often fail.
fn wait_for_usb_reset_hint(port: &mut dyn SerialPort, total: Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + total;
    port.set_timeout(Duration::from_millis(200))
        .map_err(|e| e.to_string())?;
    let mut one = [0u8; 1];
    while std::time::Instant::now() < deadline {
        match port.read(&mut one) {
            Ok(0) => continue,
            Ok(_) => continue,
            Err(_) => {
                println!("Serial read ended (device may have reset).");
                return Ok(());
            }
        }
    }
    println!("No serial error within wait window; if the device reset, CCID should appear.");
    Ok(())
}
