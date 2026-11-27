# Browser flasher (docs/flash)

`index.html` is the Fry web flasher. It uses ESP Web Tools (vendored under `vendor/`),
which reads `manifest.json` and picks the build from the chip it detects. ESP8266 is served by
`manifest-hold.json` (fw/hold/).

## Boards that are not flashed from the browser

No binaries and no manifest entries exist for these here; the page only documents how to flash
them with the release files from the GitHub releases page.

### Raspberry Pi Pico W / Pico 2 W (UF2 drag-and-drop)

1. Download the `.uf2` for your board (Pico W = RP2040, Pico 2 W = RP2350).
2. Hold BOOTSEL, plug in USB, release. A drive appears (`RPI-RP2` / `RP2350`).
3. Drag the `.uf2` onto the drive. The board reboots by itself.

### BK7231N (ltchiptool)

1. `pip install ltchiptool`
2. Wire a 3.3 V USB-serial adapter to the module TX1 / RX1 and ground.
3. `ltchiptool flash write -d <serial port> <firmware file>`, then power-cycle when asked.
