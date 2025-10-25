#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, struct

# --- Config fija ---
APP_START_ADDR    = 0x00002000
FLASH_TOTAL_SIZE  = 256 * 1024
FOOTER_ADDR       = 0x00040000 - 64  # 0x0003FFC0
KEY_FIXED         = 0xA1B2C3D4       # clave fija

# --- Constantes footer ---
ZK_FOOTER_MAGIC   = 0x5A4B5347  # 'ZKSG'
ZK_FOOTER_TAIL    = 0x474B535A  # 'GKSZ'
SIG_ALGO_CRC32K   = 0x0001

def crc32_table():
    tbl = [0]*256
    for i in range(256):
        c = i
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        tbl[i] = c
    return tbl

_CRC_TBL = crc32_table()

def crc32(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC_TBL[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF

def parse_intel_hex_collect_app(path: str):
    """Soporta records 00, 01, 04."""
    upper = 0
    mem = {}
    max_addr = APP_START_ADDR
    lines = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for raw in f:
            ln = raw.strip()
            if not ln:
                continue
            lines.append(ln)
            if not ln.startswith(':'):
                continue
            try:
                length = int(ln[1:3], 16)
                addr   = int(ln[3:7], 16)
                rtype  = int(ln[7:9], 16)
                data_hex = ln[9:9+length*2]
            except Exception:
                continue

            if rtype == 0x04:
                if length == 2:
                    upper = int(data_hex, 16) << 16
            elif rtype == 0x00:
                abs_addr = upper + addr
                b = bytes.fromhex(data_hex)
                for i, bb in enumerate(b):
                    a = abs_addr + i
                    mem[a] = bb
                    if a >= APP_START_ADDR and a + 1 > max_addr:
                        max_addr = a + 1
            elif rtype == 0x01:
                pass

    if max_addr <= APP_START_ADDR:
        raise SystemExit("ERROR: HEX sin datos de aplicación por encima de 0x2000")

    app_bytes = bytes(mem.get(a, 0xFF) for a in range(APP_START_ADDR, max_addr))
    if len(app_bytes) > (FLASH_TOTAL_SIZE - APP_START_ADDR):
        raise SystemExit("ERROR: app_size fuera de rango")

    return app_bytes, lines

def ihex_line(addr16, rtype, data_bytes):
    length = len(data_bytes)
    total = length + ((addr16 >> 8) & 0xFF) + (addr16 & 0xFF) + rtype
    for b in data_bytes:
        total += b
    total &= 0xFF
    checksum = ((~total + 1) & 0xFF)
    return ":" + "".join([
        f"{length:02X}",
        f"{addr16:04X}",
        f"{rtype:02X}",
        data_bytes.hex().upper(),
        f"{checksum:02X}",
    ])

def emit_footer_records(footer_addr, footer_bytes):
    lines = []
    upper = (footer_addr >> 16) & 0xFFFF
    ela_data = bytes([(upper >> 8) & 0xFF, upper & 0xFF])
    lines.append(ihex_line(0x0000, 0x04, ela_data))
    offs = footer_addr & 0xFFFF
    i = 0
    CHUNK = 16
    while i < len(footer_bytes):
        chunk = footer_bytes[i:i+CHUNK]
        lines.append(ihex_line(offs, 0x00, chunk))
        offs = (offs + len(chunk)) & 0xFFFF
        i += len(chunk)
    lines.append(":00000001FF")
    return lines

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    inhex  = os.path.join(script_dir, "ZerokeyOS.ino.hex")
    outhex = os.path.join(script_dir, "ZerokeyOS_signed_footer.hex")

    print(f"[INFO] Usando clave fija 0x{KEY_FIXED:08X}")
    print(f"[INFO] Leyendo: {inhex}")

    if not os.path.exists(inhex):
        print(f"❌ No se encuentra {inhex}")
        sys.exit(1)

    app_bytes, original_lines = parse_intel_hex_collect_app(inhex)
    app_size = len(app_bytes)

    crc_app = crc32(app_bytes)
    sig32   = crc32(app_bytes + struct.pack("<I", KEY_FIXED))

    # Campo u32 faltante en el pack: usamos 0
    extra_u32 = 0

    reserved = bytes(40)
    footer = struct.pack(
        "<IHHIIII40sI",
        ZK_FOOTER_MAGIC,   # I
        0x0001,            # H -> versión
        SIG_ALGO_CRC32K,   # H -> algoritmo
        app_size,          # I
        crc_app,           # I
        sig32,             # I
        extra_u32,         # I  <-- ESTE ES EL QUE FALTABA
        reserved,          # 40s
        ZK_FOOTER_TAIL,    # I
    )

    out_lines = [ln for ln in original_lines if not (ln.startswith(":") and ln[7:9].upper()=="01")]
    out_lines += emit_footer_records(FOOTER_ADDR, footer)

    with open(outhex, "w", encoding="utf-8", newline="\n") as f:
        for ln in out_lines:
            f.write(ln + "\n")

    print(f"[OK] app_size={app_size} bytes")
    print(f"[OK] crc32_app=0x{crc_app:08X}  sig32=0x{sig32:08X}")
    print(f"[OK] Footer @ 0x{FOOTER_ADDR:08X} escrito en {outhex}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
