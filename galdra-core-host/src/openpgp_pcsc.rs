//! PC/SC helpers: select OpenPGP application and read SIG slot public key (INS `0x47`, P1=`0x81`, P2=`0xB6`).
//!
//! Requires the **`pcsc`** feature (enabled by default). Building with `--no-default-features` omits
//! the native PC/SC link; callers receive [`crate::GaldraError::SmartCard`] indicating PC/SC is unavailable.

use crate::GaldraError;

#[cfg(feature = "pcsc")]
mod imp {
    use super::GaldraError;
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

    fn read_sig_public_key_bytes(card: &Card) -> Result<Vec<u8>, GaldraError> {
        select_openpgp_application(card)?;
        let mut acc: Vec<u8> = Vec::new();
        let mut cmd: Vec<u8> = vec![0x00, 0x47, 0x81, 0xB6, 0x00];
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
                    "OpenPGP read SIG public key failed: SW={sw:04X}"
                )));
            }
            let le = if sw2 == 0 { 0x00 } else { sw2 };
            cmd = vec![0x00, 0xC0, 0x00, 0x00, le];
        }
    }

    pub(super) fn read_sig_public_key_bytes_via_pcsc() -> Result<Vec<u8>, GaldraError> {
        let ctx = Context::establish(Scope::User)
            .map_err(|e| GaldraError::SmartCard(format!("PC/SC establish: {e}")))?;
        let card = connect_card(&ctx)?;
        read_sig_public_key_bytes(&card)
    }
}

#[cfg(not(feature = "pcsc"))]
mod imp {
    use super::GaldraError;

    pub(super) fn read_sig_public_key_bytes_via_pcsc() -> Result<Vec<u8>, GaldraError> {
        Err(GaldraError::SmartCard(
            "galdra-core-host was built with default-features disabled (no PC/SC); rebuild with the \
             `pcsc` feature for smart card support"
                .to_string(),
        ))
    }
}

/// Read SIG slot public key bytes from the first PC/SC reader (or `GALDRA_PCSC_READER`).
pub fn read_sig_public_key_bytes_via_pcsc() -> Result<Vec<u8>, GaldraError> {
    imp::read_sig_public_key_bytes_via_pcsc()
}
