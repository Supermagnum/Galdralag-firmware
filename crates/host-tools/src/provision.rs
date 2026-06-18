// USB CDC PIN provisioning client for Galdralag first boot (operator-chosen PINs).
//
// SPDX-License-Identifier: GPL-3.0-only

use std::io::{BufRead, BufReader};
use std::time::Duration;

use clap::Parser;
use serialport::{DataBits, Parity, SerialPort, StopBits};

/// Matches firmware `CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES` / provisioning personality cap.
const PROVISIONING_PIN_MAX: usize = 32;

#[derive(Parser, Debug)]
#[command(
    name = "galdralag-provision",
    about = "Provision User and Admin PINs over USB CDC (first boot)"
)]
struct Args {
    /// Serial device (e.g. /dev/ttyACM0)
    #[arg(long)]
    port: String,
    #[arg(long)]
    user_pin: Option<String>,
    #[arg(long)]
    admin_pin: Option<String>,
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

    let reader_port = port.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(reader_port);

    send_line(port.as_mut(), b"STATUS\n")?;
    let status = read_resp_line(&mut reader)?;
    match status.as_str() {
        "NEEDS_PROVISIONING" => {}
        "PROVISIONED" => {
            println!("Device reports PROVISIONED; nothing to do.");
            return Ok(());
        }
        other => {
            return Err(format!("unexpected STATUS response: {other:?}"));
        }
    }

    send_line(
        port.as_mut(),
        format!("SET_USER_PIN:{user_pin}\n").as_bytes(),
    )?;
    expect_ok(&mut reader)?;

    send_line(
        port.as_mut(),
        format!("SET_ADMIN_PIN:{admin_pin}\n").as_bytes(),
    )?;
    expect_ok(&mut reader)?;

    send_line(port.as_mut(), b"COMMIT\n")?;
    expect_ok(&mut reader)?;

    println!("Provisioning complete. Device should switch to CCID / OpenPGP enumeration.");
    Ok(())
}

fn send_line(port: &mut dyn SerialPort, data: &[u8]) -> Result<(), String> {
    port.write_all(data).map_err(|e| e.to_string())?;
    port.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn read_resp_line(reader: &mut impl BufRead) -> Result<String, String> {
    let mut buf = String::new();
    reader
        .read_line(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    let line = buf
        .trim_end_matches(|c| c == '\r' || c == '\n')
        .to_string();
    if line.starts_with("ERR:") {
        return Err(line);
    }
    Ok(line)
}

fn expect_ok(reader: &mut impl BufRead) -> Result<(), String> {
    let line = read_resp_line(reader)?;
    if line != "OK" {
        return Err(format!("expected OK, got {line:?}"));
    }
    Ok(())
}
