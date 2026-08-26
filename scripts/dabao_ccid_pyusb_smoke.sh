#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Direct CCID bulk smoke test on Dabao (bypasses pcscd). Use when pcsc_scan shows
# ATR once then Status unavailable.
#
# Requires: pyusb, pcscd fully stopped (service + socket), Dabao replugged after stop.
#
# Usage:
#   sudo systemctl stop pcscd.service pcscd.socket
#   # unplug/replug Dabao (runtime 1d50:6197)
#   scripts/dabao_ccid_pyusb_smoke.sh
#   sudo systemctl start pcscd.socket pcscd.service
#
# Stub bring-up image may answer XfrBlock with APDU marker CA FE 90 00 (not full SELECT).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GALDRA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HIL="${XOUS_CORE:-$(cd "${GALDRA_ROOT}/.." && pwd)/xous-core}/tools/ccid_hil"

if systemctl is-active --quiet pcscd 2>/dev/null; then
  echo "ERROR: pcscd is still active. Run:" >&2
  echo "  sudo systemctl stop pcscd.service pcscd.socket" >&2
  exit 1
fi

if ! lsusb -d 1d50:6197 >/dev/null 2>&1; then
  echo "ERROR: Dabao 1d50:6197 not found (need runtime Xous, not boot1 6196)" >&2
  exit 1
fi

if ls -la /dev/ttyACM* /dev/serial/by-id/*Baochip* 2>/dev/null; then
  echo "NOTE: ttyACM present — usually boot1 (6196) only; dabao-ccid runtime has no USB CDC log."
else
  echo "NOTE: no ttyACM on 6197 (expected for Persona A dabao-ccid)."
fi

python3 << PY
import sys
import time
sys.path.insert(0, "${HIL}")
import usb.core
import usb.util
from ccid_usb import make_get_slot_status, make_xfr_block, CcidEndpoints

VID, PID = 0x1D50, 0x6197
READ_MS = 8000
WRITE_MS = 5000

dev = usb.core.find(idVendor=VID, idProduct=PID)
if dev is None:
    raise SystemExit("device not found")

cfg = dev.get_active_configuration()
intf = next(i for i in cfg if i.bInterfaceClass == 0x0B)
if_num = intf.bInterfaceNumber
usb.util.claim_interface(dev, if_num)

def bulk_ep(intf, out):
    return usb.util.find_descriptor(
        intf,
        custom_match=lambda e: (
            usb.util.endpoint_direction(e.bEndpointAddress)
            == (usb.util.ENDPOINT_OUT if out else usb.util.ENDPOINT_IN)
            and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
        ),
    )

ep_out = bulk_ep(intf, True)
ep_in = bulk_ep(intf, False)
print(f"CCID if={if_num} ep_out={ep_out.bEndpointAddress:#x} ep_in={ep_in.bEndpointAddress:#x}")

def roundtrip_detail(name, frame):
    t0 = time.monotonic()
    try:
        nw = dev.write(ep_out.bEndpointAddress, frame, timeout=WRITE_MS)
        t_write = time.monotonic() - t0
        print(f"{name}: bulk OUT OK {nw} bytes in {t_write:.3f}s")
    except Exception as e:
        print(f"{name}: bulk OUT FAIL {type(e).__name__}: {e}", file=sys.stderr)
        return False
    t1 = time.monotonic()
    try:
        r = bytes(dev.read(ep_in.bEndpointAddress, 512, timeout=READ_MS))
        t_read = time.monotonic() - t1
        print(f"{name}: bulk IN OK {len(r)} bytes in {t_read:.3f}s: {r[:48].hex()}")
        if len(r) >= 14 and r[10:14] == bytes([0xCA, 0xFE, 0x90, 0x00]):
            print(f"{name}: stub marker CA FE 90 00 in RDR_to_PC_DataBlock (stub invoked + CcidTx)")
        return True
    except Exception as e:
        t_read = time.monotonic() - t1
        print(f"{name}: bulk IN FAIL after {t_read:.3f}s {type(e).__name__}: {e}", file=sys.stderr)
        return False

def icc_power_on(seq):
    return bytes([0x62, 0, 0, 0, 0, 0, seq & 0xFF, 0, 0, 0])

SELECT = bytes.fromhex("00A404000D D276000124010101000001".replace(" ", ""))
steps = [
    ("GetSlotStatus", make_get_slot_status(0)),
    ("IccPowerOn", icc_power_on(1)),
    ("XfrBlock SELECT", make_xfr_block(2, SELECT)),
]
failed = False
for name, frame in steps:
    if not roundtrip_detail(name, frame):
        failed = True
        print("--- post-failure inline probe (GetSlotStatus) ---", file=sys.stderr)
        roundtrip_detail("GetSlotStatus-probe", make_get_slot_status(3))
        break

raise SystemExit(1 if failed else 0)
PY
