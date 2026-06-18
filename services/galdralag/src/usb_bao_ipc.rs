//! IPC types and opcodes for the xous-core `usb-bao1x` server (`services/usb-bao1x/src/api.rs`).
//! Kept local so this crate does not link `usb-bao1x` (which would unify `pddb` features with the
//! USB service and pull incompatible `loader` / `svd2utra` into the Galdralag workspace graph).

use rkyv::{Archive, Deserialize, Serialize};

pub const SERVER_NAME_USB_DEVICE: &str = "_Xous USB device driver_";

/// `Opcode::LinkStatus` in `usb-bao1x` `api.rs`.
pub const OP_LINK_STATUS: u32 = 0;
/// `Opcode::CcidRxDeferred` when built with `ccid-openpgp`.
pub const OP_CCID_RX_DEFERRED: u32 = 640;
/// `Opcode::CcidTx` when built with `ccid-openpgp`.
pub const OP_CCID_TX: u32 = 642;

#[derive(Debug, Archive, Serialize, Deserialize, Clone)]
pub struct CcidMsgIpc {
    pub data: Vec<u8>,
    pub code: CcidCode,
}

#[derive(Debug, Archive, Serialize, Deserialize, Copy, Clone, Eq, PartialEq)]
pub enum CcidCode {
    Tx,
    TxAck,
    RxWait,
    RxAck,
    RxTimeout,
    Hangup,
    Denied,
}

/// Mirror of `usb_device::device::UsbDeviceState` used by `LinkStatus` in `usb-bao1x` `main.rs`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbDeviceState {
    Default = 0,
    Addressed = 1,
    Configured = 2,
    Suspend = 3,
}

impl UsbDeviceState {
    pub fn from_scalar(code: usize) -> Option<Self> {
        match code {
            0 => Some(Self::Default),
            1 => Some(Self::Addressed),
            2 => Some(Self::Configured),
            3 => Some(Self::Suspend),
            _ => None,
        }
    }
}
