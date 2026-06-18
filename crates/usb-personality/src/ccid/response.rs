//! Construct CCID **RDR_to_PC** bulk responses.

#![deny(unsafe_code)]

use heapless::Vec;

/// RDR_to_PC_DataBlock.
pub const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
/// RDR_to_PC_SlotStatus.
pub const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
/// RDR_to_PC_Parameters (ATR / protocol parameters).
pub const RDR_TO_PC_PARAMETERS: u8 = 0x82;

/// CCID result flags for `bStatus` / `bError` (simplified: command completed, ICC active).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CcidStatus {
    /// `bStatus`: lower two bits = ICC status (0 = present/active), upper = command status (0 = OK).
    pub b_status: u8,
    /// `bError`: CCID error code (0 = no error).
    pub b_error: u8,
    /// `bChainParameter` (chaining for TPDU).
    pub b_chain: u8,
}

impl CcidStatus {
    /// Command processed successfully; ICC present and active.
    pub const fn ok_active() -> Self {
        Self {
            b_status: 0x00,
            b_error: 0x00,
            b_chain: 0x00,
        }
    }

    /// Host message could not be handled (e.g. unknown PC_to_RDR type).
    pub const fn cmd_not_supported() -> Self {
        Self {
            b_status: 0x40,
            b_error: 0xFE,
            b_chain: 0x00,
        }
    }
}

fn push_hdr(
    out: &mut Vec<u8, 530>,
    msg_type: u8,
    dw_length: u32,
    slot: u8,
    seq: u8,
    st: &CcidStatus,
) -> Result<(), ()> {
    out.push(msg_type).map_err(|_| ())?;
    for b in dw_length.to_le_bytes() {
        out.push(b).map_err(|_| ())?;
    }
    out.push(slot).map_err(|_| ())?;
    out.push(seq).map_err(|_| ())?;
    out.push(st.b_status).map_err(|_| ())?;
    out.push(st.b_error).map_err(|_| ())?;
    out.push(st.b_chain).map_err(|_| ())?;
    Ok(())
}

/// OpenPGP smart card profile ATR (T=1), used by several implementations and GnuPG scdaemon.
pub fn atr_openpgp_profile() -> &'static [u8] {
    &[
        0x3B, 0xDA, 0x18, 0xFF, 0x81, 0xB1, 0xFE, 0x75, 0x1F, 0x03, 0x00, 0x31, 0xC5, 0x73, 0xC0,
        0x01, 0x40, 0x00, 0x90, 0x00, 0x0C,
    ]
}

/// RDR_to_PC_DataBlock (0x80): response to [`super::PcToRdr::XfrBlock`].
pub fn rdr_to_pc_data_block(
    slot: u8,
    seq: u8,
    status: CcidStatus,
    apdu_response: &[u8],
) -> Vec<u8, 530> {
    let mut out = Vec::new();
    let dw = apdu_response.len() as u32;
    let _ = push_hdr(&mut out, RDR_TO_PC_DATA_BLOCK, dw, slot, seq, &status);
    for b in apdu_response {
        let _ = out.push(*b);
    }
    out
}

/// RDR_to_PC_SlotStatus (0x81): response to [`super::PcToRdr::GetSlotStatus`] / [`super::PcToRdr::IccPowerOff`].
pub fn rdr_to_pc_slot_status(slot: u8, seq: u8, status: CcidStatus) -> Vec<u8, 530> {
    let mut out = Vec::new();
    let _ = push_hdr(&mut out, RDR_TO_PC_SLOT_STATUS, 0, slot, seq, &status);
    out
}

/// RDR_to_PC_Parameters (0x82): response to [`super::PcToRdr::IccPowerOn`] carrying the ATR.
pub fn rdr_to_pc_parameters(slot: u8, seq: u8) -> Vec<u8, 530> {
    let atr = atr_openpgp_profile();
    let mut out = Vec::new();
    let _ = push_hdr(
        &mut out,
        RDR_TO_PC_PARAMETERS,
        atr.len() as u32,
        slot,
        seq,
        &CcidStatus::ok_active(),
    );
    for b in atr {
        let _ = out.push(*b);
    }
    out
}
