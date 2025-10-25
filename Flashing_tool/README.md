# SAMD21 Flashing Tool (J-Link)

This tool flashes the bootloader and firmware to an ATSAMD21G18A (Arduino Zero) using a J-Link programmer.

---

## ✅ Requirements

- **Operating system**: Windows
- **Programmer**: SEGGER J-Link (e.g. EDU Mini, Base, etc.)
- **Software**: [J-Link Software Pack](https://www.segger.com/downloads/jlink)
- **Connection**: SWD (via pogo pins or header)

---

## 🔌 Wiring

Connect the J-Link to the SAMD21 as follows:

| J-Link Pin | SAMD21 Pin |
|------------|------------|
| SWDIO      | SWDIO      |
| SWCLK      | SWCLK      |
| RESET      | RESET      |
| GND        | GND        |

---

## 🚀 Flashing Process

1. Connect the J-Link to the board.
2. Power the board or ensure it's powered via J-Link.
3. Double-click `flash_all.bat`.
4. Wait until the process finishes (approx. 10 seconds).

Both the bootloader and firmware will be flashed automatically.

---

## 📁 Files Used

Do **not** rename or move the following files:

- `bootloader.hex`
- `firmware.bin`
- `flash_all.jlink`
- `flash_all.bat`

These files must remain in the same folder.

---
