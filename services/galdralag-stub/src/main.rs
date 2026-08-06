//! Minimal Galdralag CCID APDU stub for Dabao bring-up.
//!
//! Connects to xous-core `usb-bao1x` CCID transport, answers `IccPowerOn` with an OpenPGP ATR,
//! answers OpenPGP `SELECT` with AID + `9000`, and logs other APDUs. No PDDB, RRAM, or vault.

#[cfg(target_os = "xous")]
mod usb_bao_ipc;

#[cfg(not(target_os = "xous"))]
fn main() {
    eprintln!(
        "galdralag-stub is a Xous process; build with --target riscv32imac-unknown-xous-elf"
    );
}

#[cfg(target_os = "xous")]
fn main() -> ! {
    stub_ccid_main();
}

#[cfg(target_os = "xous")]
fn stub_ccid_main() -> ! {
    use log::info;
    use xous_names::XousNames;

    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    info!("galdralag-stub starting (PID {})", xous::process::id());

    let ticktimer = loop {
        match ticktimer::Ticktimer::new() {
            Ok(tt) => break tt,
            Err(_) => {
                xous::yield_slice();
            }
        }
    };

    let xns = loop {
        match XousNames::new() {
            Ok(x) => break x,
            Err(_) => {
                ticktimer.sleep_ms(50).ok();
            }
        }
    };

    info!("connecting to USB CCID transport");
    let usb_conn = xns
        .request_connection_blocking(usb_bao_ipc::SERVER_NAME_USB_DEVICE)
        .expect("USB device server");

    info!("USB connected; entering CCID serve loop");
    ccid_serve_loop(usb_conn);
}

#[cfg(target_os = "xous")]
fn ccid_serve_loop(usb_conn: xous::CID) -> ! {
    use usb_personality::ccid::{
        parse_pc_to_rdr, rdr_to_pc_data_block, rdr_to_pc_parameters, rdr_to_pc_slot_status,
        CcidError, CcidStatus, PcToRdr,
    };
    use usb_personality::openpgp::build_aid;

    // Fixed stub AID (manufacturer 0x20A0, serial 0x00000001).
    let stub_aid = build_aid(0x20A0, [0x00, 0x00, 0x00, 0x01]);
    let mut last_link = usb_link_status(usb_conn);

    loop {
        let st = usb_link_status(usb_conn);
        if st != last_link {
            log::info!("USB link status: {st:?}");
            last_link = st;
        }

        let frame = match ccid_rx_deferred(usb_conn) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("CcidRxDeferred: {e:?} (hangup/reset); continuing");
                continue;
            }
        };

        log::info!("PC_to_RDR {} bytes: {:02x?}", frame.len(), &frame[..frame.len().min(16)]);

        let rdr = match parse_pc_to_rdr(&frame) {
            Ok(PcToRdr::IccPowerOn { slot, seq, .. }) => {
                log::info!("IccPowerOn slot={slot} seq={seq} -> ATR");
                rdr_to_pc_parameters(slot, seq)
            }
            Ok(PcToRdr::IccPowerOff { slot, seq }) => {
                log::info!("IccPowerOff slot={slot} seq={seq}");
                rdr_to_pc_slot_status(slot, seq, CcidStatus::ok_active())
            }
            Ok(PcToRdr::GetSlotStatus { slot, seq }) => {
                log::info!("GetSlotStatus slot={slot} seq={seq}");
                rdr_to_pc_slot_status(slot, seq, CcidStatus::ok_active())
            }
            Ok(PcToRdr::Abort { slot, seq }) => {
                log::info!("Abort slot={slot} seq={seq}");
                rdr_to_pc_slot_status(slot, seq, CcidStatus::ok_active())
            }
            Ok(PcToRdr::XfrBlock { slot, seq, apdu }) => {
                log::info!("XfrBlock APDU ({}) {:02x?}", apdu.len(), apdu.as_slice());
                let apdu_resp = handle_apdu_stub(apdu.as_slice(), &stub_aid);
                log::info!("APDU response {:02x?}", apdu_resp);
                rdr_to_pc_data_block(slot, seq, CcidStatus::ok_active(), &apdu_resp)
            }
            Err(CcidError::LengthMismatch)
            | Err(CcidError::TooShort)
            | Err(CcidError::UnknownMessageType)
            | Err(CcidError::PayloadTooLarge) => {
                let slot = frame.get(5).copied().unwrap_or(0);
                let seq = frame.get(6).copied().unwrap_or(0);
                log::warn!("malformed CCID frame");
                rdr_to_pc_slot_status(slot, seq, CcidStatus::cmd_not_supported())
            }
        };

        let mut data: Vec<u8> = Vec::with_capacity(rdr.len());
        data.extend_from_slice(rdr.as_slice());

        if let Err(e) = ccid_tx(usb_conn, data) {
            log::warn!("CcidTx: {e:?}");
        }
    }
}

/// Minimal APDU handler: OpenPGP SELECT -> AID + 9000; else 6D00.
#[cfg(target_os = "xous")]
fn handle_apdu_stub(apdu: &[u8], stub_aid: &[u8; 16]) -> Vec<u8> {
    use usb_personality::openpgp::aid_matches_openpgp;

    // Need at least CLA INS P1 P2.
    if apdu.len() < 4 {
        return vec![0x6D, 0x00];
    }
    let ins = apdu[1];
    let p1 = apdu[2];
    let p2 = apdu[3];

    // SELECT by AID: CLA=00, INS=A4, P1=04, P2=00|04
    if ins == 0xA4 && p1 == 0x04 && (p2 == 0x00 || p2 == 0x04) {
        let data = if apdu.len() >= 5 {
            let lc = apdu[4] as usize;
            let start: usize = 5;
            let end = start.saturating_add(lc).min(apdu.len());
            &apdu[start..end]
        } else {
            &[][..]
        };
        // Accept full OpenPGP AID match, or prefix-only SELECT (D2 76 00 01 24).
        let openpgp = aid_matches_openpgp(data)
            || data.starts_with(usb_personality::openpgp::OPENPGP_AID_PREFIX);
        if openpgp {
            let mut out = Vec::with_capacity(stub_aid.len() + 2);
            out.extend_from_slice(stub_aid);
            out.push(0x90);
            out.push(0x00);
            return out;
        }
        return vec![0x6A, 0x82]; // file not found
    }

    vec![0x6D, 0x00]
}

#[cfg(target_os = "xous")]
fn usb_link_status(conn: xous::CID) -> usb_bao_ipc::UsbDeviceState {
    match xous::send_message(
        conn,
        xous::Message::new_blocking_scalar(usb_bao_ipc::OP_LINK_STATUS as usize, 0, 0, 0, 0),
    ) {
        Ok(xous::Result::Scalar5(_, code, _, _, _)) => usb_bao_ipc::UsbDeviceState::from_scalar(code)
            .unwrap_or(usb_bao_ipc::UsbDeviceState::Default),
        _ => usb_bao_ipc::UsbDeviceState::Default,
    }
}

#[cfg(target_os = "xous")]
fn ccid_rx_deferred(conn: xous::CID) -> Result<Vec<u8>, xous::Error> {
    use usb_bao_ipc::{CcidCode, CcidMsgIpc};
    use xous_ipc::Buffer;

    let req = CcidMsgIpc {
        data: Vec::new(),
        code: CcidCode::RxWait,
    };
    let mut buf = Buffer::into_buf(req).map_err(|_| xous::Error::InternalError)?;
    buf.lend_mut(conn, usb_bao_ipc::OP_CCID_RX_DEFERRED)
        .map_err(|_| xous::Error::InternalError)?;
    let ack = buf
        .to_original::<CcidMsgIpc, _>()
        .map_err(|_| xous::Error::InternalError)?;
    match ack.code {
        CcidCode::RxAck => Ok(ack.data),
        CcidCode::Hangup => Err(xous::Error::ProcessTerminated),
        CcidCode::Denied => Err(xous::Error::AccessDenied),
        _ => Err(xous::Error::InternalError),
    }
}

#[cfg(target_os = "xous")]
fn ccid_tx(conn: xous::CID, data: Vec<u8>) -> Result<(), xous::Error> {
    use usb_bao_ipc::{CcidCode, CcidMsgIpc};
    use xous_ipc::Buffer;

    let req = CcidMsgIpc {
        data,
        code: CcidCode::Tx,
    };
    let mut buf = Buffer::into_buf(req).map_err(|_| xous::Error::InternalError)?;
    buf.lend_mut(conn, usb_bao_ipc::OP_CCID_TX)
        .map_err(|_| xous::Error::InternalError)?;
    let ack = buf
        .to_original::<CcidMsgIpc, _>()
        .map_err(|_| xous::Error::InternalError)?;
    match ack.code {
        CcidCode::TxAck => Ok(()),
        CcidCode::Hangup => Err(xous::Error::ProcessTerminated),
        CcidCode::Denied => Err(xous::Error::AccessDenied),
        _ => Err(xous::Error::InternalError),
    }
}
