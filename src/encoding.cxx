#include "encoding.h"

uint32_t big_endian_uint32(const uint8_t buf[])
{
  uint32_t out = 0;

  out = ((uint32_t)(buf[0]) << 24) |
        ((uint32_t)(buf[1]) << 16) |
        ((uint32_t)(buf[2]) << 8) |
        ((uint32_t)(buf[3]) << 0);

  return out;
}

void big_endian_put_uint32(uint8_t *out, uint32_t v)
{
  out[0] = (uint8_t)((v >> 24) & 0xff);
  out[1] = (uint8_t)((v >> 16) & 0xff);
  out[2] = (uint8_t)((v >> 8) & 0xff);
  out[3] = (uint8_t)((v >> 0) & 0xff);
}