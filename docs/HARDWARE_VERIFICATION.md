# Hardware Verification Status

## Zeroisation

The zeroisation implementation has been tested in simulation using the
`test-hal` fake. The following hardware-level verifications have NOT yet
been performed on physical Baochip-1x silicon:

- [ ] JTAG-assisted memory inspection after triggered zeroise confirms all
  sensitive regions are overwritten.
- [ ] Power-cycle resilience: interrupted zeroise resumes correctly on next
  boot.
- [ ] Side-channel confirmation that zeroised RRAM regions do not retain
  data remnants readable by differential power analysis or similar attack.
- [ ] Confirmation that the always-on domain one-way counter correctly
  reflects the zeroise event after power loss.

## PIN counter ordering

- [ ] Hardware confirmation that RRAM flush occurs before subtle::ConstantTimeEq
  returns, under a logic analyser or equivalent.

## Stateful signature counters (XMSS/LMS)

- [ ] Hardware confirmation that the RRAM leaf index and hardware one-way
  counter are both advanced before any signature bytes leave the device.

Update this document as hardware testing is completed.
