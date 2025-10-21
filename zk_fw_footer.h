#ifndef ZK_FW_FOOTER_H
#define ZK_FW_FOOTER_H

#include <stdint.h>
#include <stddef.h>

#define FW_FOOTER_MAGIC 0x21DA07ADu
#define FW_FOOTER_SIZE 28u

typedef struct {
    uint32_t magic;
    uint32_t app_length;
    uint32_t crc32;
    uint8_t mac_tag[16];
} fw_footer_t;

#define APPLICATION_START_ADDRESS 0x00002000u
#define FLASH_END_ADDRESS         0x00008000u
#define FW_FOOTER_ADDRESS         (FLASH_END_ADDRESS - FW_FOOTER_SIZE)

#endif /* ZK_FW_FOOTER_H */
