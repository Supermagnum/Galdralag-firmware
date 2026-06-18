# dabao Pinout Documentation

## SPI/QSPI Naming Convention

**Note**: There is an unusual situation with SPI chip-select pins where both `SPI2_CS0` assignments are valid:
- Physical Pin 10 (PC3): `SPI2_CS0`
- Physical Pin 27 (PB11): `SPI2_CS0`

Both pins can function as SPI2 Chip Select 0, which may seem redundant but is intentional in the hardware design. This allows for flexibility in SPI device connections.

### SPI Formatting
- QSPI functions: `QSPI1_CS1`, `QSPI1_CS0`, `QSPI1_CLK`, `QSPI1_D3`, `QSPI1_D2`, `QSPI1_D1`, `QSPI1_D0`
- SPI2 functions: `SPI2_CS0`, `SPI2_CS1`, `SPI2_D1`, `SPI2_D0`, `SPI2_CLK`
- Both QSPI and SPI functions appear in the same SPI column

## Pin Layout

Physical pins are arranged as follows:
- **Left table**: Physical indices 1-16 (top to bottom)
- **Right table**: Physical indices 25-40 (top to bottom, with pin 40 at the top)
- **Gaps**: Physical indices 17-24 are placeholders (may contain PA4, PA5, PA6 for ADC)

## ADC Channels

ADC channels are mapped to:
- PA4 → ADC0
- PA5 → ADC1
- PA6 → ADC2

These correspond to physical pins in the 17-24 range (exact mapping TBD).

## Special Pins

- **RUN (Physical Index 30)**: Reset function (RST_N) - requires custom handling
- **ON (Physical Index 37)**: Enable function (EN) - replaces 3V3_EN naming

## Power Pins

- **VBUS (Pin 40)**: Red styling
- **VSYS (Pin 39)**: Red styling
- **3V3 (Pin 36)**: Red styling
- **GND pins**: Multiple ground pins throughout (pins 3, 8, 13, 25, 28, 33, 38)

## Data Source

Pin information is maintained in `pins.csv` with the following columns:
- Physical Index
- Pin Name
- BIO
- SPI / QSPI Functions
- I2C / UART / PWM
- ADC

## Board Information

- **Manufacturer**: Baochip
- **Board Name**: dabao
- **Based on**: [pinout-xyz/pico.pinout.xyz](https://github.com/pinout-xyz/pico.pinout.xyz) (MIT license)
