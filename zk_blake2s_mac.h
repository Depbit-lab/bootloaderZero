#ifndef ZK_BLAKE2S_MAC_H
#define ZK_BLAKE2S_MAC_H

#include <stddef.h>
#include <stdint.h>

#define BLAKE2S_MAC_LEN 16

void blake2s_mac(uint8_t *out, const void *data, size_t len, const void *key, size_t keylen);

#endif /* ZK_BLAKE2S_MAC_H */
