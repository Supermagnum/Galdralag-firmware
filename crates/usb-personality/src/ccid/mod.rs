//! USB CCID (Chip Card Interface Device) class: descriptors and message framing.
//!
//! **Security role:** transport only; cryptographic policy lives in [`crate::openpgp`].

#![deny(unsafe_code)]

mod command;
mod response;
pub mod usb_class;

pub use command::{parse_pc_to_rdr, CcidError, PcToRdr};
pub use response::{
    atr_openpgp_profile, rdr_to_pc_data_block, rdr_to_pc_parameters, rdr_to_pc_slot_status,
    CcidStatus, RDR_TO_PC_DATA_BLOCK, RDR_TO_PC_PARAMETERS, RDR_TO_PC_SLOT_STATUS,
};
pub use usb_class::CcidClass;

/// USB device class: interface defined (composite device).
pub const USB_DEVICE_CLASS: u8 = 0x00;
/// USB interface class: CCID.
pub const USB_INTERFACE_CLASS_CCID: u8 = 0x0B;
/// USB interface subclass / protocol for CCID (no CCID protocol over USB bulk).
pub const USB_INTERFACE_SUBCLASS_CCID: u8 = 0x00;
pub const USB_INTERFACE_PROTOCOL_CCID: u8 = 0x00;

/// pid.codes test VID for open-source hardware.
pub const USB_VID_GALDRALAG: u16 = 0x20A0;
/// Product ID (Baochip-1x / Galdralag token allocation).
pub const USB_PID_GALDRALAG_TOKEN: u16 = 0x42B3;

/// USB string descriptor indices (host reads UTF-16; indices assigned by integrator).
pub const STRING_INDEX_MANUFACTURER: u8 = 1;
pub const STRING_INDEX_PRODUCT: u8 = 2;
pub const STRING_INDEX_SERIAL: u8 = 3;

/// Manufacturer string for USB descriptor (UTF-8; firmware encodes to UTF-16).
pub const USB_STRING_MANUFACTURER: &str = "Galdralag Project";
/// Product string for USB descriptor.
pub const USB_STRING_PRODUCT: &str = "Galdralag Security Token";

/// CCID class descriptor `bcdCCID` (1.10).
pub const CCID_BCD_CCID: u16 = 0x0110;
/// One logical slot (index 0).
pub const CCID_MAX_SLOT_INDEX: u8 = 0x00;
/// 5V, 3V, 1.8V.
pub const CCID_VOLTAGE_SUPPORT: u8 = 0x07;
/// T=1 only (`dwProtocols` bit 1).
pub const CCID_DW_PROTOCOLS: u32 = 0x0000_0002;
pub const CCID_DW_DEFAULT_CLOCK: u32 = 0x0000_0FA0;
pub const CCID_DW_MAXIMUM_CLOCK: u32 = 0x0000_0FA0;
pub const CCID_DW_DATA_RATE: u32 = 0x0000_2580;
pub const CCID_DW_MAX_DATA_RATE: u32 = 0x0000_2580;
pub const CCID_DW_MAX_IFSD: u32 = 0xFE;
pub const CCID_DW_SYNCH_PROTOCOLS: u32 = 0;
pub const CCID_DW_MECHANICAL: u32 = 0;
/// Auto configuration, voltage, clock, baud, PPS, APDU level exchange.
pub const CCID_DW_FEATURES: u32 = 0x0004_00FE;
pub const CCID_MAX_MESSAGE_LENGTH: u32 = 0x10F;
pub const CCID_CLASS_GET_RESPONSE: u8 = 0xFF;
pub const CCID_CLASS_ENVELOPE: u8 = 0xFF;
pub const CCID_LCD_LAYOUT: u16 = 0;
pub const CCID_PIN_SUPPORT: u8 = 0x00;
pub const CCID_MAX_BUSY_SLOTS: u8 = 0x01;

/// Bulk endpoint max packet size (high-speed).
pub const CCID_BULK_MAX_PACKET: u16 = 512;
/// Interrupt endpoint max packet size.
pub const CCID_INTERRUPT_MAX_PACKET: u16 = 8;
/// Interrupt polling interval (frames; 24 ms at full speed).
pub const CCID_INTERRUPT_INTERVAL_MS: u8 = 24;

/// Maximum PC_to_RDR / RDR_to_PC message size (bytes) for this stack (header + payload).
pub const CCID_WIRE_BUF_SIZE: usize = 530;

/// Raw CCID functional descriptor payload (follows interface descriptor in configuration).
///
/// Length = 0x36 (54) bytes for this layout per USB CCID 1.10.
pub fn ccid_class_descriptor_bytes() -> [u8; 54] {
    let mut b = [0u8; 54];
    b[0] = 0x21;
    b[1] = 0x36;
    b[2..4].copy_from_slice(&CCID_BCD_CCID.to_le_bytes());
    b[4] = CCID_MAX_SLOT_INDEX;
    b[5] = CCID_VOLTAGE_SUPPORT;
    b[6..10].copy_from_slice(&CCID_DW_PROTOCOLS.to_le_bytes());
    b[10..14].copy_from_slice(&CCID_DW_DEFAULT_CLOCK.to_le_bytes());
    b[14..18].copy_from_slice(&CCID_DW_MAXIMUM_CLOCK.to_le_bytes());
    b[18..22].copy_from_slice(&CCID_DW_DATA_RATE.to_le_bytes());
    b[22..26].copy_from_slice(&CCID_DW_MAX_DATA_RATE.to_le_bytes());
    b[26..30].copy_from_slice(&CCID_DW_MAX_IFSD.to_le_bytes());
    b[30..34].copy_from_slice(&CCID_DW_SYNCH_PROTOCOLS.to_le_bytes());
    b[34..38].copy_from_slice(&CCID_DW_MECHANICAL.to_le_bytes());
    b[38..42].copy_from_slice(&CCID_DW_FEATURES.to_le_bytes());
    b[42..46].copy_from_slice(&CCID_MAX_MESSAGE_LENGTH.to_le_bytes());
    b[46] = CCID_CLASS_GET_RESPONSE;
    b[47] = CCID_CLASS_ENVELOPE;
    b[48..50].copy_from_slice(&CCID_LCD_LAYOUT.to_le_bytes());
    b[50] = CCID_PIN_SUPPORT;
    b[51] = CCID_MAX_BUSY_SLOTS;
    b
}
