#pragma once

#include <cstdint>

uint32_t big_endian_uint32(const uint8_t out[]);

void big_endian_put_uint32(uint8_t *out, uint32_t v);