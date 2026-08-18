//! Galdralag CCID handler for Xous: IPC to `usb-bao1x`, OpenPGP dispatch via [`usb_personality`] +
//! [`baochip_openpgp`]. PDDB `usb.ccid` keys from provisioning (see xous-core `ccid_store.rs`) are
//! bridged into RRAM before [`open_or_provision_backend`].

#[cfg(all(feature = "board-dabao", feature = "board-baosec"))]
compile_error!("enable only one of board-dabao or board-baosec");

#[cfg(all(target_os = "xous", feature = "board-dabao"))]
mod dabao_stub;

#[cfg(target_os = "xous")]
mod usb_bao_ipc;

#[cfg(not(target_os = "xous"))]
fn main() {
    eprintln!("galdralag-service is a Xous process; build with --target riscv32imac-unknown-xous-elf \
               and feature xous-bsp.");
}

#[cfg(target_os = "xous")]
fn main() -> ! {
    galdralag_ccid_main();
}

#[cfg(target_os = "xous")]
fn galdralag_ccid_main() -> ! {
    use std::cell::RefCell;
    use std::rc::Rc;

    use bao1x_hal::rram::Reram;
    use baochip_openpgp::{
        ccid_pin_hashes_unprovisioned, load_or_derive_ccid_master_key, map_openpgp_rram_windows,
        open_or_provision_backend, write_provisioning_pins, BaochipVaultBackend,
    };
    use log::info;
    use usb_personality::openpgp::OpenPgpCcidDispatcher;
    use xous_names::XousNames;

    const KEY_USER_LINE: &str = "user_pin_line";
    const KEY_ADMIN_LINE: &str = "admin_pin_line";
    #[cfg(feature = "board-dabao")]
    const PDDB_WAIT_RETRIES: u32 = 60;
    #[cfg(feature = "board-dabao")]
    const RRAM_MAP_RETRIES: u32 = 3;

    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    info!("galdralag-service starting (PID {})", xous::process::id());

    let ticktimer = loop {
        match ticktimer::Ticktimer::new() {
            Ok(tt) => break tt,
            Err(_) => {
                // Spawn can trail essential services; match xous-core ordering tolerance (retry loops).
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

    let pddb = pddb::Pddb::new();

    let mut reram = Reram::new();

    #[cfg(feature = "board-dabao")]
    let rram_mapped = {
        let mut ok = false;
        for attempt in 1..=RRAM_MAP_RETRIES {
            match map_openpgp_rram_windows(&mut reram) {
                Ok(()) => {
                    ok = true;
                    break;
                }
                Err(e) => {
                    log::error!(
                        "map OpenPGP RRAM failed (attempt {attempt}/{RRAM_MAP_RETRIES}): {:?}",
                        e
                    );
                    ticktimer.sleep_ms(100).ok();
                }
            }
        }
        if !ok {
            log::warn!(
                "OpenPGP RRAM mapping unavailable on Dabao; starting CCID with bring-up stub \
                 (UnsupportedVaultStorage path; vault APDUs return unsupported)"
            );
        }
        ok
    };

    #[cfg(not(feature = "board-dabao"))]
    {
        map_openpgp_rram_windows(&mut reram).expect("map OpenPGP RRAM");
    }

    #[cfg(feature = "board-dabao")]
    if !rram_mapped {
        let aid = build_id_aid();
        let backend = dabao_stub::DabaoBringupBackend::new(aid);
        let mut dispatcher = OpenPgpCcidDispatcher::new(backend);
        let usb_conn = xns
            .request_connection_blocking(usb_bao_ipc::SERVER_NAME_USB_DEVICE)
            .expect("USB device server");
        info!("vault stub ready; connecting to USB stack for CCID");
        ccid_serve_loop(&mut dispatcher, usb_conn);
    }

    // Dabao + RRAM mapped: connect USB immediately. usb-bao1x answers IccPowerOn /
    // GetSlotStatus inline; this process serves deferred XfrBlock (bring-up stub
    // until vault is ready, then BaochipVaultBackend).
    #[cfg(feature = "board-dabao")]
    {
        let rram = Rc::new(RefCell::new(reram));
        let usb_conn = xns
            .request_connection_blocking(usb_bao_ipc::SERVER_NAME_USB_DEVICE)
            .expect("USB device server");
        info!("early USB connect; deferred APDUs until vault ready");

        let mut stub = OpenPgpCcidDispatcher::new(dabao_stub::DabaoBringupBackend::new(build_id_aid()));
        let mut last_link = usb_link_status(usb_conn);
        let vault_wait_start = ticktimer.elapsed_ms();
        let pddb_wait_ms = (PDDB_WAIT_RETRIES as u64).saturating_mul(500);
        let mut pin_lines: Option<(Vec<u8>, Vec<u8>)> = None;

        loop {
            if pin_lines.is_none() {
                if ccid_pddb_provisioned(&pddb) {
                    let user_line = read_pddb_key(&pddb, KEY_USER_LINE, 256);
                    let admin_line = read_pddb_key(&pddb, KEY_ADMIN_LINE, 256);
                    match (user_line, admin_line) {
                        (Ok(u), Ok(a)) if !u.is_empty() && !a.is_empty() => {
                            pin_lines = Some((u, a));
                        }
                        _ => {
                            info!("OKV1 set but pin lines missing; retrying after CCID");
                        }
                    }
                } else if ticktimer.elapsed_ms().saturating_sub(vault_wait_start) >= pddb_wait_ms {
                    log::warn!(
                        "PDDB usb.ccid OKV1 not seen after {} x 500ms; continuing without \
                         PDDB provisioning data (Dabao development defaults)",
                        PDDB_WAIT_RETRIES
                    );
                    // PW Status max PW1=5 / max PW3=8 (see DEFAULT_PW_STATUS_BYTES).
                    pin_lines = Some((b"12345".to_vec(), b"12345678".to_vec()));
                }
            }

            if let Some((ref user_line, ref admin_line)) = pin_lines {
                let vault_ok = (|| -> Option<BaochipVaultBackend> {
                    if ccid_pin_hashes_unprovisioned(&rram) {
                        info!("bridging PIN lines to RRAM provision slots");
                        if let Err(e) = write_provisioning_pins(&rram, user_line, admin_line) {
                            log::error!("write_provisioning_pins: {:?}", e);
                            return None;
                        }
                    }

                    let device_binding = std::env::var("PUBLIC_SERIAL")
                        .unwrap_or_else(|_| "DABAODEV".into())
                        .into_bytes();

                    let mut trng = match trng::Trng::new(&xns) {
                        Ok(t) => t,
                        Err(e) => {
                            log::error!("trng: {:?}", e);
                            return None;
                        }
                    };
                    let master_key =
                        match load_or_derive_ccid_master_key(&rram, &mut trng, &device_binding) {
                            Ok(k) => k,
                            Err(e) => {
                                log::error!("load_or_derive_ccid_master_key: {:?}", e);
                                return None;
                            }
                        };

                    let aid = build_id_aid();
                    let first_pin_bridge = ccid_pin_hashes_unprovisioned(&rram);
                    let backend = match open_or_provision_backend(
                        rram.clone(),
                        &xns,
                        master_key,
                        aid,
                        user_line,
                        admin_line,
                    ) {
                        Ok(b) => b,
                        Err(e) => {
                            log::error!("open_or_provision_backend: {:?}", e);
                            return None;
                        }
                    };

                    if first_pin_bridge {
                        // TODO(contact-store): map contact-store RRAM + call ContactStore::provision_fresh
                        // after vault open; treat AlreadyProvisioned as non-fatal, other errors as fatal.
                        info!(
                            "first PIN bridge complete; contact-store provision_fresh pending HAL wiring"
                        );
                    }
                    Some(backend)
                })();

                if let Some(backend) = vault_ok {
                    info!("vault ready; switching from stub to full OpenPGP backend");
                    let mut dispatcher = OpenPgpCcidDispatcher::new(backend);
                    ccid_serve_loop(&mut dispatcher, usb_conn);
                }
            }

            // One deferred CCID frame (XfrBlock / other). 0x62/0x65 are not TXed here.
            ccid_dispatch_one(&mut stub, usb_conn, &mut last_link);
        }
    }

    // Baosec: vault must be ready before USB connect (unchanged sequence).
    #[cfg(not(feature = "board-dabao"))]
    {
        let rram = Rc::new(RefCell::new(reram));

        let mut dispatcher = 'vault: {
            loop {
                let (user_line, admin_line) = if ccid_pddb_provisioned(&pddb) {
                    let user_line = match read_pddb_key(&pddb, KEY_USER_LINE, 256) {
                        Ok(v) if !v.is_empty() => v,
                        _ => {
                            info!("OKV1 set but user_pin_line missing; retrying");
                            ticktimer.sleep_ms(500).ok();
                            continue;
                        }
                    };
                    let admin_line = match read_pddb_key(&pddb, KEY_ADMIN_LINE, 256) {
                        Ok(v) if !v.is_empty() => v,
                        _ => {
                            info!("OKV1 set but admin_pin_line missing; retrying");
                            ticktimer.sleep_ms(500).ok();
                            continue;
                        }
                    };
                    (user_line, admin_line)
                } else {
                    info!("waiting for usb.ccid provisioned sentinel (OKV1)...");
                    ticktimer.sleep_ms(500).ok();
                    continue;
                };

                if ccid_pin_hashes_unprovisioned(&rram) {
                    info!("bridging PIN lines to RRAM provision slots");
                    if let Err(e) = write_provisioning_pins(&rram, &user_line, &admin_line) {
                        log::error!("write_provisioning_pins: {:?}", e);
                        ticktimer.sleep_ms(500).ok();
                        continue;
                    }
                }

                let device_binding = std::env::var("PUBLIC_SERIAL")
                    .expect("PUBLIC_SERIAL")
                    .into_bytes();

                let mut trng = trng::Trng::new(&xns).expect("trng");
                let master_key =
                    match load_or_derive_ccid_master_key(&rram, &mut trng, &device_binding) {
                        Ok(k) => k,
                        Err(e) => {
                            log::error!("load_or_derive_ccid_master_key: {:?}", e);
                            ticktimer.sleep_ms(500).ok();
                            continue;
                        }
                    };

                let aid = build_id_aid();

                let first_pin_bridge = ccid_pin_hashes_unprovisioned(&rram);
                let backend: BaochipVaultBackend = match open_or_provision_backend(
                    rram.clone(),
                    &xns,
                    master_key,
                    aid,
                    &user_line,
                    &admin_line,
                ) {
                    Ok(b) => b,
                    Err(e) => {
                        log::error!("open_or_provision_backend: {:?}", e);
                        ticktimer.sleep_ms(500).ok();
                        continue;
                    }
                };

                if first_pin_bridge {
                    // TODO(contact-store): map contact-store RRAM + call ContactStore::provision_fresh
                    // after vault open; treat AlreadyProvisioned as non-fatal, other errors as fatal.
                    info!(
                        "first PIN bridge complete; contact-store provision_fresh pending HAL wiring"
                    );
                }

                info!("vault ready; connecting to USB stack for CCID");
                break 'vault OpenPgpCcidDispatcher::new(backend);
            }
        };

        let usb_conn = xns
            .request_connection_blocking(usb_bao_ipc::SERVER_NAME_USB_DEVICE)
            .expect("USB device server");

        ccid_serve_loop(&mut dispatcher, usb_conn);
    }
}

#[cfg(target_os = "xous")]
fn build_id_aid() -> [u8; 16] {
    let serial = std::env::var("PUBLIC_SERIAL").unwrap_or_default();
    let mut s4 = [0u8; 4];
    let b = serial.as_bytes();
    let n = b.len().min(4);
    s4[..n].copy_from_slice(&b[..n]);
    usb_personality::openpgp::build_aid(0x20A0, s4)
}

#[cfg(target_os = "xous")]
fn ccid_pddb_provisioned(pddb: &pddb::Pddb) -> bool {
    use std::io::Read;
    const KEY_PROVISIONED: &str = "provisioned";
    const CCID_DICT: &str = "usb.ccid";
    match pddb.get(
        CCID_DICT,
        KEY_PROVISIONED,
        None,
        false,
        false,
        Some(32),
        None::<fn()>,
    ) {
        Ok(mut key) => {
            let mut buf = [0u8; 32];
            match key.read(&mut buf) {
                Ok(n) if n >= 4 => &buf[..n] == b"OKV1",
                _ => false,
            }
        }
        Err(_) => false,
    }
}

#[cfg(target_os = "xous")]
fn read_pddb_key(pddb: &pddb::Pddb, name: &str, max: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    const CCID_DICT: &str = "usb.ccid";
    let mut key = pddb.get(CCID_DICT, name, None, false, false, Some(max), None::<fn()>)?;
    let mut buf = vec![0u8; max];
    let n = key.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

#[cfg(target_os = "xous")]
fn ccid_dispatch_one<B: usb_personality::openpgp::OpenPgpBackend>(
    dispatcher: &mut usb_personality::openpgp::OpenPgpCcidDispatcher<B>,
    usb_conn: xous::CID,
    last_link: &mut usb_bao_ipc::UsbDeviceState,
) {
    use usb_personality::ccid::rdr_to_pc_slot_status;
    use usb_personality::ccid::{parse_pc_to_rdr, CcidError, CcidStatus};
    use usb_personality::openpgp::OpenPgpDispatch;

    let st = usb_link_status(usb_conn);
    if st != *last_link {
        if st != usb_bao_ipc::UsbDeviceState::Configured {
            log::info!("USB link not configured ({st:?}); resetting OpenPGP session");
            dispatcher.on_usb_reset();
        }
        *last_link = st;
    }

    let frame = match ccid_rx_deferred(usb_conn) {
        Ok(f) => f,
        Err(e) => {
            log::warn!("CcidRxDeferred: {:?}", e);
            dispatcher.on_usb_reset();
            return;
        }
    };

    let rdr = match parse_pc_to_rdr(&frame) {
        Ok(pc) => {
            if pc.answered_inline_by_usb_bao1x() {
                log::debug!(
                    "dropping PC_to_RDR that usb-bao1x answers inline (IccPowerOn/GetSlotStatus); not CcidTx"
                );
                return;
            }
            dispatcher.handle_ccid(pc)
        }
        Err(CcidError::LengthMismatch)
        | Err(CcidError::TooShort)
        | Err(CcidError::UnknownMessageType)
        | Err(CcidError::PayloadTooLarge) => {
            let slot = frame.get(5).copied().unwrap_or(0);
            let seq = frame.get(6).copied().unwrap_or(0);
            log::warn!("dropping malformed CCID frame");
            rdr_to_pc_slot_status(slot, seq, CcidStatus::cmd_not_supported())
        }
    };

    let mut data: Vec<u8> = Vec::with_capacity(rdr.len());
    data.extend_from_slice(rdr.as_slice());

    if let Err(e) = ccid_tx(usb_conn, data) {
        log::warn!("CcidTx: {:?}", e);
        dispatcher.on_usb_reset();
    }
}

#[cfg(target_os = "xous")]
fn ccid_serve_loop<B: usb_personality::openpgp::OpenPgpBackend>(
    dispatcher: &mut usb_personality::openpgp::OpenPgpCcidDispatcher<B>,
    usb_conn: xous::CID,
) -> ! {
    let mut last_link = usb_link_status(usb_conn);
    loop {
        ccid_dispatch_one(dispatcher, usb_conn, &mut last_link);
    }
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
