# How to make a suitable PCB for a USB dongle

This document describes how to create a **modified PCB** for a **USB-A security dongle** based on the Baochip **Dabao** reference, using **[KiCad](https://www.kicad.org/)** for layout and **[FreeCAD](https://www.freecad.org/)** for a **mechanical enclosure** fitted to the board and connector.

**Upstream board:** clone or fork **[github.com/baochip/dabao](https://github.com/baochip/dabao)** as the starting point.

---

## Why a dedicated dongle layout (vs the stock Dabao board)

The **Dabao** evaluation board follows a **Raspberry Pi Pico**–style layout: **40 pins** along the **edges** (castellated / through-hole header). That is **ideal for firmware testing** (breadboard, logic probes, shields). A **USB dongle** product does **not** need that exposed GPIO; the goal is a **compact** board with **USB-A** and the **SoC** (and **optional QSPI PSRAM**), not a development breakout. This guide assumes you **remove** the Pico header and related area to free space for **edge-mount USB-A** and **PSRAM routing** — same silicon and power tree as the reference, **different** outline and connector strategy.

---

## Why USB-A on the PCB edge

- **Mechanical strength:** A **USB Type-A** plug implemented as **gold fingers on the PCB** (or a through-hole USB-A male) is **more robust** in many lab and field uses than a small **USB-C** receptacle and flexing cable: the **dongle body** can surround a wide plug area and the insertion force is spread across a **wider, simpler** tongue.
- **Host compatibility:** **Type-A** sockets are still **very common** on desktops, hubs, and industrial panels; carrying a **USB-A male** token avoids depending on **USB-C** cables and **Alternate Mode** confusion for a simple HID/CCID device.
- **Power (no PD):** A **USB 2.0 Type-A** port supplies **5 V**. A configured low-power device may draw up to **500 mA** (five **100 mA** unit loads) on a compliant host port — **no USB Power Delivery negotiation**, no **CC** pin logic. That is enough for many token-class boards with modest buck front ends.
- **USB-C contrast:** **Type-C** can offer **higher voltage and current**, but doing so normally involves **USB PD** (and **CC** channel) **negotiation**, more complex **cable and receptacle** rules, and extra **firmware** where a simple **5 V** dongle does not need it.

The design below **replaces the USB-C connector** routing with **edge pads** for a **USB-A** footprint while keeping the **Baochip** core and power tree unchanged.

---

## Toolchain: KiCad and FreeCAD

| Tool | Role | Link |
|------|------|------|
| **KiCad** | Schematic capture, PCB layout, fabrication outputs (Gerber, drill, BOM), **3D export** of the assembled board. | [kicad.org](https://www.kicad.org/) — [documentation](https://docs.kicad.org/) |
| **FreeCAD** | **Parametric CAD** for the **enclosure**: shell, strain relief around the **USB-A tongue**, clips, labels. | [freecad.org](https://www.freecad.org/) — [documentation](https://wiki.freecad.org/) |

### Enclosure workflow (PCB to solid model)

1. **Finish** the PCB in KiCad (board outline, component placement, USB-A edge connector geometry).
2. **Export** the board assembly for mechanical use. Common paths:
   - **STEP** (or **VRML**) from KiCad’s **File → Export** (exact menu varies by KiCad 7/8/9; see [PCB editor export](https://docs.kicad.org/master/en/pcb_editor/pcb_editor.html) in the current manual). STEP is preferred for **dimensionally accurate** solids in CAD.
3. **Import** the STEP file into **FreeCAD** (**File → Import**). You now have the **board thickness, outline, and USB-A protrusion** as reference geometry.
4. **Model** the enclosure **around** the imported PCB: inner clearance, **USB-A slot** width/depth to match the standard plug, snap features, and print orientation for **FDM** or **SLS**.

Optional: the **KiCad StepUp** ecosystem (community workbenches) can align KiCad and FreeCAD more tightly; for many projects, **plain STEP import** into FreeCAD is enough to build a shell **directly** around the board and connector.

---

## Board outline

| Dimension | Target |
|-----------|--------|
| **Width** | Minimum **12 mm**, maximum **~15 mm** |
| **Length** | **40–60 mm** total **including** the **plug** section, depending on how much electronics are inside |

---

## Remove

- **Pico** castellated header footprint and **all** its copper.
- **SW1** push button.

---

## Replace / fix

- **SW1** → Pull **RST_N** high via a **10 kΩ** resistor to **3.3 V** with a **100 nF** cap to **GND** for clean power-on reset. Same function, **no button**.
- **SW2** → **EN** pin pulled **fixed high** via resistor to **3.3 V**. Remove the button; **keep** the pull resistor.
- **EN** held permanently asserted means the buck converters are **always enabled** when **VBUS** is present — correct for a **dongle**.

---

## Add

- **USB-A** gold fingers on the **PCB edge**, or a proper **USB-A male** plug — **4 pads**: **VBUS**, **D−**, **D+**, **GND** at standard USB-A spacing (**2.5 mm** pitch, **12 mm** total width). The **PCB edge** can **be** the plug.
- **ENIG** finish (already specified on many fabs) so the **contact fingers** are gold-bearing.
- **IS66WVR8M8FALL** (SOIC-8) or **equivalent** PSRAM footprint in the space freed by removing the Pico header.

---

## Reroute

- **USBC_P** → **D+** edge pad.
- **USBC_N** → **D−** edge pad.
- **VBUS** → **VBUS** edge pad.
- **GND** → **GND** edge pad.
- **CC1 / CC2** resistors → **DNP** (not needed for USB-A; leave footprints, mark **do-not-populate**).
- **PC0–PC3** → test pads on PCB bottom or **unconnected**.

---

## Quad-SPI bus (PSRAM)

| Baochip signal | PSRAM |
|----------------|-------|
| BIO23 (QSPI1D0) | SIO0 |
| BIO24 (QSPI1D1) | SIO1 |
| BIO25 (QSPI1D2) | SIO2 |
| BIO26 (QSPI1D3) | SIO3 |
| BIO27 (QSPI1CLK) | CLK |
| BIO28 (QSPI1CS0) | CE# |

### PSRAM power and decoupling

- **VCC** → **3.3 V** rail (already present).
- **GND** → **GND**.
- One **100 nF** + one **10 µF** decoupling cap close to the PSRAM **VCC** pin — same **0201** (or your house) size as elsewhere.

Keep **power planes** and **power infrastructure** components intact; move **only** what is needed to fit the new outline. **Refill** copper pours after edits.

---

## Power and SoC (unchanged)

That is the **complete functional change list** for this dongle variant. **Nothing** in the power **architecture** changes:

- Both **MT3406** buck converters, all their passives, the **crystal**, and all **Baochip-1x BGA decoupling** stay **exactly** where they are on the reference design.

---

## Fabrication and publication

1. Run **DRC** and **ERC** in KiCad.
2. Output **Gerbers**, **drill**, **pick-and-place** (if applicable), and **BOM**.
3. Optionally export **STEP** for the **enclosure** in FreeCAD as above.
4. Archive fabrication files in your **repository** (e.g. `hardware/` releases or tagged commits) and **publish** on GitHub with a short **README** pointing to this document.
