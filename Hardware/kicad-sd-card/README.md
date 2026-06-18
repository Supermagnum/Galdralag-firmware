# Dabao board design files (SD card)

This directory contains the KiCad design files for the Dabao USB-A security token with the Baochip-1x. This revision adds a micro-SD card holder (`dabao_v3c_sdcard` project).

**Outputs and previews**

- [dabao_v3c_sdcard.pdf](dabao_v3c_sdcard.pdf) — schematic / design PDF export  
- [dabao_v3c_sdcard.jpg](dabao_v3c_sdcard.jpg) — top of the PCB (render or photo)  
- [dabao_v3c_sdcard-b.jpg](dabao_v3c_sdcard-b.jpg) — bottom of the PCB

**Enclosure — FreeCAD source**

- [Enclosure/Enclosure.FCStd](Enclosure/Enclosure.FCStd) — FreeCAD project file (`.FCStd`). Open it in [FreeCAD](https://www.freecad.org/), a free, open-source parametric 3D modeler for Windows, macOS, and Linux.

**Enclosure — STL for 3D printing**

- [Enclosure/stl-files/](Enclosure/stl-files/) — STL (STereoLithography) triangle meshes exported from the enclosure CAD. Use these files with a slicer for FDM or resin printing; they include the top and bottom shell, PCB reference solid, and screw part meshes.

**Enclosure — STEP (STP) for CAD**

- [Enclosure/stp-files/](Enclosure/stp-files/) — STEP / STP files (ISO 10303) exported from the enclosure model. These are precise solid models for import into CAD or CAM tools (machining, further editing, or mesh conversion), including body assemblies and screw parts.
