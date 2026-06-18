//! USB CCID class implementation for [`usb_device::class::UsbClass`].
//!
//! **Security role:** transport only; parses PC_to_RDR frames and forwards APDUs to
//! [`crate::openpgp::dispatch::OpenPgpDispatch`].

#![deny(unsafe_code)]

use heapless::Vec;
use usb_device::class::UsbClass;
use usb_device::class_prelude::*;
use usb_device::Result as UsbResult;
use usb_device::UsbError;

use super::ccid_class_descriptor_bytes;
use super::parse_pc_to_rdr;
use super::rdr_to_pc_slot_status;
use super::CcidStatus;
use super::CCID_WIRE_BUF_SIZE;
use crate::openpgp::dispatch::OpenPgpDispatch;

/// USB CCID class driver: bulk OUT/IN plus interrupt IN for slot notifications.
pub struct CcidClass<'a, B: UsbBus, D: OpenPgpDispatch> {
    iface: InterfaceNumber,
    bulk_out: EndpointOut<'a, B>,
    bulk_in: EndpointIn<'a, B>,
    interrupt_in: EndpointIn<'a, B>,
    protocol: CcidProtocolState<D>,
}

/// CCID message assembly and dispatch without USB I/O (unit-tested).
pub(crate) struct CcidProtocolState<D: OpenPgpDispatch> {
    dispatch: D,
    rx_buf: Vec<u8, CCID_WIRE_BUF_SIZE>,
    tx_buf: Vec<u8, CCID_WIRE_BUF_SIZE>,
    tx_pending: bool,
}

fn remove_prefix<const N: usize>(v: &mut Vec<u8, N>, n: usize) {
    let len = v.len();
    if n >= len {
        v.clear();
        return;
    }
    for i in 0..len - n {
        v[i] = v[i + n];
    }
    v.truncate(len - n);
}

impl<D: OpenPgpDispatch> CcidProtocolState<D> {
    pub(crate) fn new(dispatch: D) -> Self {
        Self {
            dispatch,
            rx_buf: Vec::new(),
            tx_buf: Vec::new(),
            tx_pending: false,
        }
    }

    pub(crate) fn push_out_bytes(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.rx_buf.len().saturating_add(data.len()) > CCID_WIRE_BUF_SIZE {
            self.rx_buf.clear();
            return;
        }
        let _ = self.rx_buf.extend_from_slice(data);
        self.try_dispatch();
    }

    fn try_dispatch(&mut self) {
        if self.rx_buf.len() < 10 {
            return;
        }
        let dw_length = u32::from_le_bytes(self.rx_buf[1..5].try_into().unwrap_or([0; 4])) as usize;
        let total = 10usize.saturating_add(dw_length);
        if total > CCID_WIRE_BUF_SIZE {
            self.rx_buf.clear();
            self.tx_buf = rdr_to_pc_slot_status(0, 0, CcidStatus::cmd_not_supported());
            self.tx_pending = true;
            return;
        }
        if self.rx_buf.len() < total {
            return;
        }

        let mut msg = Vec::<u8, CCID_WIRE_BUF_SIZE>::new();
        if msg.extend_from_slice(&self.rx_buf[..total]).is_err() {
            self.rx_buf.clear();
            return;
        }
        remove_prefix(&mut self.rx_buf, total);

        match parse_pc_to_rdr(msg.as_slice()) {
            Ok(pc_msg) => {
                self.tx_buf = self.dispatch.handle_ccid(pc_msg);
                self.tx_pending = true;
            }
            Err(_) => {
                self.tx_buf = rdr_to_pc_slot_status(0, 0, CcidStatus::cmd_not_supported());
                self.tx_pending = true;
            }
        }
    }

    pub(crate) fn poll_bulk_in_inner<F>(&mut self, mut write: F)
    where
        F: FnMut(&[u8]) -> usb_device::Result<usize>,
    {
        if !self.tx_pending || self.tx_buf.is_empty() {
            return;
        }
        let chunk_len = self.tx_buf.len().min(64);
        let chunk = &self.tx_buf[..chunk_len];
        match write(chunk) {
            Ok(n) => {
                remove_prefix(&mut self.tx_buf, n);
                if self.tx_buf.is_empty() {
                    self.tx_pending = false;
                }
            }
            Err(UsbError::WouldBlock) => {}
            Err(_) => {
                self.tx_pending = false;
                self.tx_buf.clear();
            }
        }
    }

    pub(crate) fn reset(&mut self) {
        self.rx_buf.clear();
        self.tx_buf.clear();
        self.tx_pending = false;
        self.dispatch.on_usb_reset();
    }
}

impl<'a, B: UsbBus, D: OpenPgpDispatch> CcidClass<'a, B, D> {
    /// Allocate endpoints and create the class. Call before the bus is enabled.
    pub fn new(alloc: &'a UsbBusAllocator<B>, dispatch: D) -> Self {
        Self {
            iface: alloc.interface(),
            bulk_out: alloc.bulk(64),
            bulk_in: alloc.bulk(64),
            interrupt_in: alloc.interrupt(8, 24),
            protocol: CcidProtocolState::new(dispatch),
        }
    }

}

#[cfg(test)]
impl<D: OpenPgpDispatch> CcidProtocolState<D> {
    pub(crate) fn dispatch_mut(&mut self) -> &mut D {
        &mut self.dispatch
    }

    pub(crate) fn rx_len(&self) -> usize {
        self.rx_buf.len()
    }
}

impl<'a, B: UsbBus, D: OpenPgpDispatch> UsbClass<B> for CcidClass<'a, B, D> {
    fn get_configuration_descriptors(&self, writer: &mut usb_device::descriptor::DescriptorWriter) -> UsbResult<()> {
        writer.interface(
            self.iface,
            super::USB_INTERFACE_CLASS_CCID,
            super::USB_INTERFACE_SUBCLASS_CCID,
            super::USB_INTERFACE_PROTOCOL_CCID,
        )?;
        let fd = ccid_class_descriptor_bytes();
        writer.write(0x21, &fd[2..])?;
        writer.endpoint(&self.bulk_out)?;
        writer.endpoint(&self.bulk_in)?;
        writer.endpoint(&self.interrupt_in)?;
        Ok(())
    }

    fn reset(&mut self) {
        self.protocol.reset();
    }

    fn poll(&mut self) {
        let ep = &self.bulk_in;
        self.protocol.poll_bulk_in_inner(|chunk| ep.write(chunk));
    }

    fn endpoint_out(&mut self, addr: EndpointAddress) {
        if addr != self.bulk_out.address() {
            return;
        }
        let mut tmp = [0u8; 64];
        if let Ok(n) = self.bulk_out.read(&mut tmp) {
            self.protocol.push_out_bytes(&tmp[..n]);
        }
    }
}

// --- Unit tests: protocol layer (no `UsbBus` required) ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccid::command::PcToRdr;
    use crate::ccid::rdr_to_pc_data_block;
    use crate::ccid::CCID_WIRE_BUF_SIZE;
    use crate::ccid::RDR_TO_PC_DATA_BLOCK;
    use crate::ccid::RDR_TO_PC_SLOT_STATUS;

    struct MockDispatch {
        pub handle_calls: usize,
        pub reset_calls: usize,
    }

    impl MockDispatch {
        fn new() -> Self {
            Self {
                handle_calls: 0,
                reset_calls: 0,
            }
        }
    }

    impl OpenPgpDispatch for MockDispatch {
        fn handle_ccid(&mut self, msg: PcToRdr) -> Vec<u8, CCID_WIRE_BUF_SIZE> {
            self.handle_calls += 1;
            if matches!(msg, PcToRdr::XfrBlock { .. }) {
                let payload = [0xABu8; 100];
                rdr_to_pc_data_block(0, 0, CcidStatus::ok_active(), &payload)
            } else {
                rdr_to_pc_slot_status(0, 0, CcidStatus::ok_active())
            }
        }

        fn on_usb_reset(&mut self) {
            self.reset_calls += 1;
        }
    }

    fn hdr(t: u8, dw_len: u32, slot: u8, seq: u8, b7: u8, b8: u8, b9: u8) -> [u8; 10] {
        let mut h = [0u8; 10];
        h[0] = t;
        h[1..5].copy_from_slice(&dw_len.to_le_bytes());
        h[5] = slot;
        h[6] = seq;
        h[7] = b7;
        h[8] = b8;
        h[9] = b9;
        h
    }

    #[test]
    fn single_packet_dispatch() {
        let apdu = [0x00u8, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
        let mut m = Vec::<u8, CCID_WIRE_BUF_SIZE>::new();
        let h = hdr(0x6F, apdu.len() as u32, 0, 1, 0, 0, 0);
        m.extend_from_slice(&h).unwrap();
        m.extend_from_slice(&apdu).unwrap();

        let mut p = CcidProtocolState::new(MockDispatch::new());
        p.push_out_bytes(m.as_slice());

        assert_eq!(p.dispatch_mut().handle_calls, 1);
        assert!(p.tx_pending);
        assert_eq!(p.tx_buf[0], RDR_TO_PC_DATA_BLOCK);
    }

    #[test]
    fn multi_packet_assembly() {
        let payload = [0xABu8; 60];
        let mut m = Vec::<u8, CCID_WIRE_BUF_SIZE>::new();
        let h = hdr(0x6F, payload.len() as u32, 0, 2, 0, 0, 0);
        m.extend_from_slice(&h).unwrap();
        m.extend_from_slice(&payload).unwrap();
        assert_eq!(m.len(), 70);

        let mut p = CcidProtocolState::new(MockDispatch::new());
        p.push_out_bytes(&m[..64]);
        assert_eq!(p.dispatch_mut().handle_calls, 0);
        p.push_out_bytes(&m[64..]);
        assert_eq!(p.dispatch_mut().handle_calls, 1);
    }

    #[test]
    fn reset_clears_state() {
        let mut p = CcidProtocolState::new(MockDispatch::new());
        p.push_out_bytes(&[0x62, 0, 0, 0, 0]);
        assert_eq!(p.rx_len(), 5);
        p.reset();
        assert_eq!(p.rx_len(), 0);
        assert_eq!(p.dispatch_mut().reset_calls, 1);

        let apdu = [0x00u8, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
        let mut m = Vec::<u8, CCID_WIRE_BUF_SIZE>::new();
        let h = hdr(0x6F, apdu.len() as u32, 0, 1, 0, 0, 0);
        m.extend_from_slice(&h).unwrap();
        m.extend_from_slice(&apdu).unwrap();
        p.push_out_bytes(m.as_slice());
        assert_eq!(p.dispatch_mut().handle_calls, 1);
    }

    #[test]
    fn malformed_message_does_not_panic() {
        let mut p = CcidProtocolState::new(MockDispatch::new());
        p.push_out_bytes(&[0xFF; 10]);
        assert_eq!(p.dispatch_mut().handle_calls, 0);
        assert!(p.tx_pending);
        assert_eq!(p.tx_buf[0], RDR_TO_PC_SLOT_STATUS);
        assert_eq!(p.tx_buf[1], 0);
    }

    #[test]
    fn poll_bulk_in_chunks_via_closure() {
        let mut p = CcidProtocolState::new(MockDispatch::new());
        let mut apdu = Vec::<u8, 512>::new();
        for _ in 0..80 {
            let _ = apdu.push(0xCC);
        }
        let mut m = Vec::<u8, CCID_WIRE_BUF_SIZE>::new();
        let h = hdr(0x6F, apdu.len() as u32, 0, 0, 0, 0, 0);
        m.extend_from_slice(&h).unwrap();
        m.extend_from_slice(apdu.as_slice()).unwrap();
        p.push_out_bytes(m.as_slice());
        assert_eq!(p.dispatch_mut().handle_calls, 1);

        let mut out = Vec::<u8, 256>::new();
        let mut writer = |chunk: &[u8]| -> usb_device::Result<usize> {
            for b in chunk {
                out.push(*b).map_err(|_| UsbError::BufferOverflow)?;
            }
            Ok(chunk.len())
        };
        while p.tx_pending {
            p.poll_bulk_in_inner(&mut writer);
        }
        assert!(out.len() > 64);
    }
}
