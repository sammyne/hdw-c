#include "hdw/internal/hmac.h"

#include <mbedtls/md.h>

//int hmac512(uint8_t md[64], const vector<uint8_t> &key, const vector<uint8_t> &msg)
int hmac512(
    uint8_t md[64], const uint8_t *key, int key_len, const uint8_t *data, int data_len)
{
  mbedtls_md_context_t ctx;

  int err = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1);
  if (err)
  {
    return -1;
  }

  err = mbedtls_md_hmac_starts(&ctx, key, key_len);
  if (err)
  {
    return -2;
  }

  err = mbedtls_md_hmac_update(&ctx, data, data_len);
  if (err)
  {
    return -3;
  }

  err = mbedtls_md_hmac_finish(&ctx, md);
  if (err)
  {
    return -4;
  }

  return 0;
}