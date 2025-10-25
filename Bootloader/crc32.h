#pragma once

#include <stddef.h>
#include <stdint.h>

uint32_t crc32_update(uint32_t crc, const void *data, size_t len);
uint32_t crc32_compute(const void *data, size_t len);
