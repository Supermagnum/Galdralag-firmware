This is needed to create a modified pcb.
With: minimum 12 mm 
Lenght:  40–60 mm total including the plug section, depending on how much electronics are inside.

Remove:

Pico castellated header footprint and all its copper
SW1 push button

Replace/fix:

SW1 → pull RST_N high via a 10kΩ resistor to 3.3V with a 100nF cap to GND for clean power-on reset. Same function, no button.
SW2 → EN pin pulled fixed high via resistor to 3.3V. Remove the button, keep the pull resistor. 
EN held permanently asserted means the buck converters are always enabled when VBUS is present, which is correct behaviour for a dongle.

Add:

USB-A gold fingers on the PCB edge, or a proper USB-A male plug — 4 pads: VBUS, D−, D+, GND at standard USB-A spacing (2.5 mm pitch, 12 mm total width). The PCB edge itself becomes the plug. 
ENIG finish already specified so the gold is already there.
IS66WVR8M8FALL SOIC-8 or others footprint in the space freed by removing the Pico header.

Reroute:
USBC_P → D+ edge pad
USBC_N → D− edge pad
VBUS → VBUS edge pad
GND → GND edge pad
CC1/CC2 resistors → DNP (not needed for USB-A, leave footprints, mark do-not-populate)
PC0–PC3 → test pads on PCB bottom or simply unconnected
BIO23 (QSPI1D0) → PSRAM SIO0
BIO24 (QSPI1D1) → PSRAM SIO1
BIO25 (QSPI1D2) → PSRAM SIO2
BIO26 (QSPI1D3) → PSRAM SIO3
BIO27 (QSPI1CLK) → PSRAM CLK
BIO28 (QSPI1CS0) → PSRAM CE#

PSRAM power and decoupling:

VCC → 3.3V rail (already present)
GND → GND
One 100nF + one 10µF decoupling cap close to the PSRAM VCC pin — same 0201 size already used throughout.
Keep power planes and power infrastructure components intact, move components to fit on the new pcb only if needed.

That is the complete change list. Nothing about the power infrastructure changes. 
Both MT3406 buck converters, all their passives, the crystal, and all the Baochip-1x BGA decoupling stay exactly where they are. 
