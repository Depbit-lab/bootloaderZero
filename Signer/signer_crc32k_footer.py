#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import struct
import sys

from intelhex import IntelHex

APP_START_ADDR = 0x00002000
FLASH_TOTAL_SIZE = 256 * 1024
FOOTER_ADDR = 0x00040000 - 64

ZK_FOOTER_MAGIC = 0x5A4B5347  # 'ZKSG'
ZK_FOOTER_TAIL = 0x474B535A
SIG_ALGO_CRC32K = 0x0001
ZK_CRC32K_KEY = 0x5A17C39D ^ 0xA5A5A5A5


def crc32(data: bytes) -> int:
    table = [0] * 256
    for i in range(256):
        c = i
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        table[i] = c

    crc = 0xFFFFFFFF
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Firma un .hex añadiendo un footer de 64 bytes en 0x0003FFC0 (CRC32+K)."
    )
    parser.add_argument("inhex", help="Input .hex (app)")
    parser.add_argument("-o", "--outhex", help="Output .hex", required=True)
    parser.add_argument(
        "--footer-only",
        action="store_true",
        help="Generar un .hex que solo contiene el footer",
    )
    args = parser.parse_args()

    ih = IntelHex()
    ih.fromfile(args.inhex, format="hex")

    max_addr = APP_START_ADDR
    for addr in ih.addresses():
        if addr < APP_START_ADDR:
            continue
        if ih[addr] != 0xFF:
            max_addr = max(max_addr, addr + 1)

    app_size = max(0, max_addr - APP_START_ADDR)
    if app_size == 0:
        print("ERROR: no se detecta aplicación por encima de 0x2000", file=sys.stderr)
        sys.exit(1)

    if app_size > (FLASH_TOTAL_SIZE - APP_START_ADDR):
        print("ERROR: app_size fuera de rango", file=sys.stderr)
        sys.exit(1)

    app_bytes = bytes(
        ih[addr] if addr in ih else 0xFF
        for addr in range(APP_START_ADDR, APP_START_ADDR + app_size)
    )

    crc_app = crc32(app_bytes)
    sig32 = crc32(app_bytes + struct.pack("<I", ZK_CRC32K_KEY))

    reserved = bytes(40)
    footer = struct.pack(
        "<IHHIIII40sI",
        ZK_FOOTER_MAGIC,
        0x0001,
        SIG_ALGO_CRC32K,
        app_size,
        crc_app,
        sig32,
        reserved,
        ZK_FOOTER_TAIL,
    )

    out_hex = IntelHex()
    if not args.footer_only:
        out_hex.merge(ih, overlap="replace")

    for i, byte in enumerate(footer):
        out_hex[FOOTER_ADDR + i] = byte

    out_hex.write_hex_file(args.outhex)

    print(
        "OK: app_size={:d} bytes, crc32_app=0x{:08X}, sig32=0x{:08X}".format(
            app_size, crc_app, sig32
        )
    )
    print(f"Footer @ 0x{FOOTER_ADDR:08X} escrito en {args.outhex}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
