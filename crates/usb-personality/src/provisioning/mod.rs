// SPDX-License-Identifier: GPL-3.0-only
//
//! One-time **USB CDC-ACM** provisioning personality: line-oriented PIN staging for `PNU1` / `PNA1`.
//!
//! Used when OpenPGP PIN verifier state is unprovisioned and silent TRNG PIN fallback is disabled.
//! The platform USB service supplies [`ProvisioningCommit`] to persist staged PINs to RRAM.

#![deny(unsafe_code)]

use galdr_core::HalError;
use heapless::Vec;
use usb_device::class::UsbClass;
use usb_device::class_prelude::*;
use usb_device::control::{Recipient, RequestType};
use usb_device::descriptor::DescriptorWriter;
use usb_device::Result as UsbResult;
use usb_device::UsbError;
use zeroize::{Zeroize, Zeroizing};

/// Maximum PIN payload bytes (matches `CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES`).
pub const PROVISIONING_PIN_MAX: usize = 32;
const LINE_CAP: usize = 96;
const TX_CAP: usize = 64;

/// Default line coding for GET_LINE_CODING: 115200 8N1.
const LINE_CODING: [u8; 7] = [0x00, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x08];

const USB_CLASS_CDC: u8 = 0x02;
const USB_CDC_SUBCLASS_ACM: u8 = 0x02;
const USB_CDC_PROTOCOL_AT: u8 = 0x01;
const USB_CLASS_CDC_DATA: u8 = 0x0A;
const CS_INTERFACE: u8 = 0x24;

/// Writes staged user + admin PINs to provision slots (`PNU1` / `PNA1`).
pub trait ProvisioningCommit {
    fn commit_pins(&mut self, user_pin: &[u8], admin_pin: &[u8]) -> Result<(), HalError>;
}

/// Minimal CDC-ACM device class with bulk line protocol for operator PIN entry.
pub struct ProvisioningClass<'a, B: UsbBus, C: ProvisioningCommit + ?Sized> {
    if_comm: InterfaceNumber,
    if_data: InterfaceNumber,
    ep_comm_in: EndpointIn<'a, B>,
    ep_data_out: EndpointOut<'a, B>,
    ep_data_in: EndpointIn<'a, B>,
    rx_line: Vec<u8, LINE_CAP>,
    tx_buf: Vec<u8, TX_CAP>,
    tx_pending: bool,
    staged_user: Zeroizing<[u8; PROVISIONING_PIN_MAX]>,
    staged_user_len: u8,
    staged_admin: Zeroizing<[u8; PROVISIONING_PIN_MAX]>,
    staged_admin_len: u8,
    commit_ok: bool,
    commit: &'a mut C,
}

impl<'a, B: UsbBus, C: ProvisioningCommit + ?Sized> ProvisioningClass<'a, B, C> {
    /// Allocate control + data interfaces and endpoints. Call before the bus is enabled.
    pub fn new(alloc: &'a UsbBusAllocator<B>, commit: &'a mut C) -> Self {
        let if_comm = alloc.interface();
        let if_data = alloc.interface();
        Self {
            if_comm,
            if_data,
            ep_comm_in: alloc.interrupt(8, 255),
            ep_data_out: alloc.bulk(64),
            ep_data_in: alloc.bulk(64),
            rx_line: Vec::new(),
            tx_buf: Vec::new(),
            tx_pending: false,
            staged_user: Zeroizing::new([0u8; PROVISIONING_PIN_MAX]),
            staged_user_len: 0,
            staged_admin: Zeroizing::new([0u8; PROVISIONING_PIN_MAX]),
            staged_admin_len: 0,
            commit_ok: false,
            commit,
        }
    }

    /// `true` after a successful `COMMIT`.
    pub fn commit_succeeded(&self) -> bool {
        self.commit_ok
    }

    fn queue_response(&mut self, text: &str) {
        self.tx_buf.clear();
        for b in text.as_bytes() {
            if self.tx_buf.push(*b).is_err() {
                break;
            }
        }
        self.tx_pending = !self.tx_buf.is_empty();
    }

    fn queue_err(&mut self, reason: &str) {
        self.tx_buf.clear();
        let _ = self.tx_buf.extend_from_slice(b"ERR:");
        for b in reason.as_bytes() {
            if self.tx_buf.push(*b).is_err() {
                break;
            }
        }
        let _ = self.tx_buf.push(b'\n');
        self.tx_pending = true;
    }

    fn process_complete_line(&mut self) {
        let line_owned = match core::str::from_utf8(self.rx_line.as_slice()) {
            Ok(s) => {
                let trimmed = s.trim_end_matches(|c| c == '\r' || c == '\n');
                let mut hs = heapless::String::<LINE_CAP>::new();
                if hs.push_str(trimmed).is_err() {
                    self.rx_line.clear();
                    self.queue_err("line too long");
                    return;
                }
                hs
            }
            Err(_) => {
                self.rx_line.clear();
                self.queue_err("invalid utf-8");
                return;
            }
        };
        self.rx_line.clear();
        let line = line_owned.as_str();

        if line == "STATUS" {
            if self.commit_ok {
                self.queue_response("PROVISIONED\n");
            } else {
                self.queue_response("NEEDS_PROVISIONING\n");
            }
            return;
        }

        if line == "COMMIT" {
            if self.staged_user_len == 0 || self.staged_admin_len == 0 {
                self.queue_err("missing pin");
                return;
            }
            let u = &self.staged_user[..self.staged_user_len as usize];
            let a = &self.staged_admin[..self.staged_admin_len as usize];
            match self.commit.commit_pins(u, a) {
                Ok(()) => {
                    self.commit_ok = true;
                    self.staged_user_len = 0;
                    self.staged_admin_len = 0;
                    self.staged_user.zeroize();
                    self.staged_admin.zeroize();
                    self.queue_response("OK\n");
                }
                Err(HalError::Denied) => self.queue_err("denied"),
                Err(HalError::NeedsProvisioning) => self.queue_err("not ready"),
                Err(_) => self.queue_err("commit failed"),
            }
            return;
        }

        const UP: &str = "SET_USER_PIN:";
        const AP: &str = "SET_ADMIN_PIN:";
        if let Some(rest) = line.strip_prefix(UP) {
            self.set_staged_pin(rest, true);
        } else if let Some(rest) = line.strip_prefix(AP) {
            self.set_staged_pin(rest, false);
        } else {
            self.queue_err("invalid command");
        }
    }

    fn set_staged_pin(&mut self, pin: &str, user: bool) {
        let b = pin.as_bytes();
        if b.is_empty() || b.len() > PROVISIONING_PIN_MAX {
            self.queue_err("pin length");
            return;
        }
        if user {
            self.staged_user.zeroize();
            self.staged_user[..b.len()].copy_from_slice(b);
            self.staged_user_len = b.len() as u8;
        } else {
            self.staged_admin.zeroize();
            self.staged_admin[..b.len()].copy_from_slice(b);
            self.staged_admin_len = b.len() as u8;
        }
        self.queue_response("OK\n");
    }

    fn drain_tx(&mut self) {
        if !self.tx_pending || self.tx_buf.is_empty() {
            return;
        }
        let chunk = self.tx_buf.as_slice();
        match self.ep_data_in.write(chunk) {
            Ok(n) => {
                if n == 0 {
                    return;
                }
                let total = self.tx_buf.len();
                if n >= total {
                    self.tx_buf.clear();
                    self.tx_pending = false;
                } else {
                    for i in 0..total - n {
                        self.tx_buf[i] = self.tx_buf[i + n];
                    }
                    self.tx_buf.truncate(total - n);
                }
            }
            Err(UsbError::WouldBlock) => {}
            Err(_) => {
                self.tx_pending = false;
                self.tx_buf.clear();
            }
        }
    }
}

impl<'a, B: UsbBus, C: ProvisioningCommit + ?Sized> UsbClass<B> for ProvisioningClass<'a, B, C> {
    fn get_configuration_descriptors(&self, writer: &mut DescriptorWriter) -> UsbResult<()> {
        writer.iad(
            self.if_comm,
            2,
            USB_CLASS_CDC,
            USB_CDC_SUBCLASS_ACM,
            USB_CDC_PROTOCOL_AT,
            None,
        )?;

        writer.interface(
            self.if_comm,
            USB_CLASS_CDC,
            USB_CDC_SUBCLASS_ACM,
            USB_CDC_PROTOCOL_AT,
        )?;
        writer.write(CS_INTERFACE, &[0x00, 0x10, 0x01])?;
        writer.write(CS_INTERFACE, &[0x02, 0x02])?;
        writer.write(
            CS_INTERFACE,
            &[0x06, self.if_comm.into(), self.if_data.into()],
        )?;
        writer.write(CS_INTERFACE, &[0x01, 0x03, self.if_data.into()])?;
        writer.endpoint(&self.ep_comm_in)?;

        writer.interface(self.if_data, USB_CLASS_CDC_DATA, 0x00, 0x00)?;
        writer.endpoint(&self.ep_data_out)?;
        writer.endpoint(&self.ep_data_in)?;
        Ok(())
    }

    fn reset(&mut self) {
        self.rx_line.clear();
        self.tx_buf.clear();
        self.tx_pending = false;
    }

    fn poll(&mut self) {
        self.drain_tx();
    }

    fn control_out(&mut self, xfer: usb_device::class::ControlOut<'_, '_, '_, B>) {
        let req = xfer.request();
        if req.request_type != RequestType::Class || req.recipient != Recipient::Interface {
            return;
        }
        if req.index as u8 != self.if_comm.into() {
            return;
        }
        match req.request {
            0x22 | 0x20 => {
                let _ = xfer.accept();
            }
            _ => {}
        }
    }

    fn control_in(&mut self, xfer: usb_device::class::ControlIn<'_, '_, '_, B>) {
        let req = xfer.request();
        if req.request_type != RequestType::Class || req.recipient != Recipient::Interface {
            return;
        }
        if req.index as u8 != self.if_comm.into() {
            return;
        }
        if req.request == 0x21 {
            let _ = xfer.accept_with(&LINE_CODING);
        }
    }

    fn endpoint_out(&mut self, addr: EndpointAddress) {
        if addr != self.ep_data_out.address() {
            return;
        }
        let mut tmp = [0u8; 64];
        if let Ok(n) = self.ep_data_out.read(&mut tmp) {
            for byte in &tmp[..n] {
                if self.rx_line.push(*byte).is_err() {
                    self.rx_line.clear();
                    self.queue_err("line too long");
                    return;
                }
                if *byte == b'\n' {
                    self.process_complete_line();
                    return;
                }
            }
        }
    }
}

impl<'a, B: UsbBus, C: ProvisioningCommit + ?Sized> Drop for ProvisioningClass<'a, B, C> {
    fn drop(&mut self) {
        self.staged_user.zeroize();
        self.staged_admin.zeroize();
        self.staged_user_len = 0;
        self.staged_admin_len = 0;
    }
}
