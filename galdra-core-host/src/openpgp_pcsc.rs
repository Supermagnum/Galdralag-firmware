//! PC/SC helpers: select OpenPGP application, read data objects, and detect stale P-512 attributes.
//!
//! Requires the **`pcsc`** feature (enabled by default). Building with `--no-default-features` omits
//! the native PC/SC link; callers receive [`crate::GaldraError::SmartCard`] indicating PC/SC is unavailable.

use crate::openpgp_card_attrs::{OpenPgpKeySlot, StaleP512Slot};
use crate::GaldraError;

/// Summary of an OpenPGP card visible via PC/SC (read-only; no card writes).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OpenPgpCardScan {
    /// Whether the OpenPGP application could be selected on a reader.
    pub card_present: bool,
    /// Slots whose C1/C2/C3 still encode BrainpoolP512r1.
    pub stale_p512_slots: Vec<StaleP512Slot>,
}

impl OpenPgpCardScan {
    /// True when any slot still reports the retired P-512 algorithm attributes.
    pub fn has_stale_p512(&self) -> bool {
        !self.stale_p512_slots.is_empty()
    }
}

#[cfg(feature = "pcsc")]
mod imp {
    use super::{OpenPgpCardScan, OpenPgpKeySlot, StaleP512Slot, GaldraError};
    use crate::openpgp_card_attrs;
    use pcsc::{Card, Context, Protocols, Scope, ShareMode};

    const SW_OK: u16 = 0x9000;

    fn combine_sw(sw1: u8, sw2: u8) -> u16 {
        (u16::from(sw1) << 8) | u16::from(sw2)
    }

    fn transmit(card: &Card, apdu: &[u8]) -> Result<(Vec<u8>, u16), GaldraError> {
        let mut recv = vec![0u8; 1024];
        let response = card
            .transmit(apdu, &mut recv)
            .map_err(|e| GaldraError::SmartCard(format!("PC/SC transmit failed: {e}")))?;
        if response.len() < 2 {
            return Err(GaldraError::SmartCard(
                "PC/SC response too short".to_string(),
            ));
        }
        let l = response.len();
        let sw1 = response[l - 2];
        let sw2 = response[l - 1];
        let sw = combine_sw(sw1, sw2);
        let data = response[..l - 2].to_vec();
        Ok((data, sw))
    }

    /// Read a complete response body, following `61xx` GET RESPONSE chaining.
    fn transmit_collect(card: &Card, initial_cmd: Vec<u8>) -> Result<Vec<u8>, GaldraError> {
        let mut acc = Vec::new();
        let mut cmd = initial_cmd;
        loop {
            let (body, sw) = transmit(card, &cmd)?;
            acc.extend_from_slice(&body);
            if sw == SW_OK {
                return Ok(acc);
            }
            let sw1 = (sw >> 8) as u8;
            let sw2 = (sw & 0xFF) as u8;
            if sw1 != 0x61 {
                return Err(GaldraError::SmartCard(format!(
                    "OpenPGP command failed: SW={sw:04X}"
                )));
            }
            let le = if sw2 == 0 { 0x00 } else { sw2 };
            cmd = vec![0x00, 0xC0, 0x00, 0x00, le];
        }
    }

    /// Select the OpenPGP card application using a small set of common partial AIDs.
    fn select_openpgp_application(card: &Card) -> Result<(), GaldraError> {
        const CANDIDATES: &[&[u8]] = &[
            &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x03, 0x04],
            &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x02, 0x00],
            &[0xD2, 0x76, 0x00, 0x01, 0x24],
        ];
        for aid in CANDIDATES {
            let mut apdu = Vec::with_capacity(5 + aid.len());
            apdu.extend_from_slice(&[0x00, 0xA4, 0x04, 0x00, aid.len() as u8]);
            apdu.extend_from_slice(aid);
            let (_, sw) = transmit(card, &apdu)?;
            if sw == SW_OK {
                return Ok(());
            }
        }
        Err(GaldraError::SmartCard(
            "could not SELECT OpenPGP application (check pcscd and card present)".to_string(),
        ))
    }

    fn connect_card(ctx: &Context) -> Result<Card, GaldraError> {
        let names = ctx
            .list_readers_owned()
            .map_err(|e| GaldraError::SmartCard(format!("list_readers: {e}")))?;
        let preferred = std::env::var("GALDRA_PCSC_READER").ok();
        let reader = if let Some(ref want) = preferred {
            names
                .iter()
                .find(|r| r.to_string_lossy() == *want)
                .ok_or_else(|| {
                    GaldraError::SmartCard(format!(
                        "PC/SC reader {:?} not found (from GALDRA_PCSC_READER)",
                        want
                    ))
                })?
        } else {
            names.first().ok_or_else(|| {
                GaldraError::SmartCard(
                    "no PC/SC readers found (start pcscd and plug in card)".to_string(),
                )
            })?
        };
        ctx.connect(reader.as_c_str(), ShareMode::Shared, Protocols::ANY)
            .map_err(|e| GaldraError::SmartCard(format!("connect: {e}")))
    }

    fn read_do(card: &Card, tag: u16) -> Result<Vec<u8>, GaldraError> {
        let p1 = (tag >> 8) as u8;
        let p2 = (tag & 0xFF) as u8;
        let cmd = vec![0x00, 0xCA, p1, p2, 0x00];
        transmit_collect(card, cmd)
    }

    fn with_openpgp_card<T>(f: impl FnOnce(&Card) -> Result<T, GaldraError>) -> Result<T, GaldraError> {
        let ctx = Context::establish(Scope::User)
            .map_err(|e| GaldraError::SmartCard(format!("PC/SC establish: {e}")))?;
        let card = connect_card(&ctx)?;
        select_openpgp_application(&card)?;
        f(&card)
    }

    fn read_sig_public_key_bytes(card: &Card) -> Result<Vec<u8>, GaldraError> {
        transmit_collect(card, vec![0x00, 0x47, 0x81, 0xB6, 0x00])
    }

    fn scan_stale_p512_slots(card: &Card) -> Result<Vec<StaleP512Slot>, GaldraError> {
        let sig = read_do(card, OpenPgpKeySlot::Sig.do_tag())?;
        let dec = read_do(card, OpenPgpKeySlot::Dec.do_tag())?;
        let aut = read_do(card, OpenPgpKeySlot::Aut.do_tag())?;
        Ok(openpgp_card_attrs::stale_p512_slots_from_do_bytes(
            &sig, &dec, &aut,
        ))
    }

    pub(super) fn read_sig_public_key_bytes_via_pcsc() -> Result<Vec<u8>, GaldraError> {
        with_openpgp_card(read_sig_public_key_bytes)
    }

    pub(super) fn scan_openpgp_card_via_pcsc() -> OpenPgpCardScan {
        // TODO(openpgp-vendor-filter): After Baochip-1x hardware bring-up, obtain an FSFE/GnuPG
        // registered OpenPGP card manufacturer ID (AID bytes 7-8 per spec; GET DATA tag 0x004F).
        // Filter here before C1/C2/C3 GET DATA so `device status` does not attribute stale-P512
        // warnings to third-party OpenPGP cards in the first PC/SC reader. Do not use USB VID
        // 0x20A0 as the filter value — it is not the OpenPGP registry field (see docs/OPENPGP_CARD.md
        // and betrusted-io/xous-core#875). Until then, any OpenPGP card that SELECT succeeds on
        // is scanned (read-only GET DATA only).
        match with_openpgp_card(scan_stale_p512_slots) {
            Ok(stale_p512_slots) => OpenPgpCardScan {
                card_present: true,
                stale_p512_slots,
            },
            Err(_) => OpenPgpCardScan {
                card_present: false,
                stale_p512_slots: Vec::new(),
            },
        }
    }

    pub(super) fn preflight_openpgp_slot_via_pcsc(slot: OpenPgpKeySlot) -> Result<(), GaldraError> {
        with_openpgp_card(|card| {
            let data = read_do(card, slot.do_tag())?;
            if let Some(stale) = openpgp_card_attrs::stale_p512_slot_from_do_bytes(slot, &data) {
                return Err(GaldraError::RemovedLegacyCrypto(stale.message));
            }
            Ok(())
        })
    }

}

#[cfg(not(feature = "pcsc"))]
mod imp {
    use super::{OpenPgpCardScan, OpenPgpKeySlot, GaldraError};

    const NO_PCSC: &str = "galdra-core-host was built with default-features disabled (no PC/SC); \
                            rebuild with the `pcsc` feature for smart card support";

    pub(super) fn read_sig_public_key_bytes_via_pcsc() -> Result<Vec<u8>, GaldraError> {
        Err(GaldraError::SmartCard(NO_PCSC.to_string()))
    }

    pub(super) fn scan_openpgp_card_via_pcsc() -> OpenPgpCardScan {
        OpenPgpCardScan {
            card_present: false,
            stale_p512_slots: Vec::new(),
        }
    }

    pub(super) fn preflight_openpgp_slot_via_pcsc(_slot: OpenPgpKeySlot) -> Result<(), GaldraError> {
        Err(GaldraError::SmartCard(NO_PCSC.to_string()))
    }
}

/// Read SIG slot public key bytes from the first PC/SC reader (or `GALDRA_PCSC_READER`).
pub fn read_sig_public_key_bytes_via_pcsc() -> Result<Vec<u8>, GaldraError> {
    imp::read_sig_public_key_bytes_via_pcsc()
}

/// Scan C1/C2/C3 via PC/SC for stale BrainpoolP512r1 algorithm attributes (read-only).
pub fn scan_openpgp_card_via_pcsc() -> OpenPgpCardScan {
    imp::scan_openpgp_card_via_pcsc()
}

/// Fail fast when a slot's stored attributes still name BrainpoolP512r1.
pub fn preflight_openpgp_slot_via_pcsc(slot: OpenPgpKeySlot) -> Result<(), GaldraError> {
    imp::preflight_openpgp_slot_via_pcsc(slot)
}

#[cfg(all(test, feature = "pcsc"))]
mod hardware_tests {
    use super::*;

    #[test]
    #[ignore = "requires OpenPGP card on a PC/SC reader"]
    fn scan_stale_p512_on_hardware() {
        let scan = scan_openpgp_card_via_pcsc();
        assert!(scan.card_present, "expected OpenPGP card via PC/SC");
        let _ = scan.stale_p512_slots;
    }
}
