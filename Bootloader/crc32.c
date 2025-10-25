#include "crc32.h"

uint32_t crc32_update(uint32_t crc, const void *data, size_t len) {
    static uint32_t table[256];
    static int init = 0;

    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        init = 1;
    }

    crc ^= 0xFFFFFFFFu;

    const uint8_t *p = (const uint8_t *)data;
    for (size_t n = 0; n < len; ++n) {
        crc = table[(crc ^ p[n]) & 0xFFu] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFFu;
}

uint32_t crc32_compute(const void *data, size_t len) {
    return crc32_update(0u, data, len);
}
