#pragma once

#include <stdint.h>

#define ZK_FOOTER_MAGIC   0x5A4B5347u  /* 'ZKSG' */
#define ZK_FOOTER_TAIL    0x474B535Au  /* 'GK SZ' inverted due to endianness */

typedef struct __attribute__((packed)) {
    uint32_t magic;       // ZK_FOOTER_MAGIC
    uint16_t version;     // 0x0001
    uint16_t algo;        // SIG_ALGO_CRC32K
    uint32_t app_size;    // actual application size in bytes
    uint32_t crc32_app;   // CRC32(app) without key (informational)
    uint32_t sig32;       // CRC32(app || K) validated by the bootloader
    uint8_t  reserved[40];// Reserved for future use (e.g., HMAC-SHA256 plus metadata)
    uint32_t tail_magic;  // ZK_FOOTER_TAIL
} zk_footer_t;

_Static_assert(sizeof(zk_footer_t) == 64, "Footer must be exactly 64 bytes");
