#include "hmac.h"

#include <mbedtls/md.h>

int hmac512(uint8_t md[64], const vector<uint8_t> &key, const vector<uint8_t> &msg)
{
  mbedtls_md_context_t ctx;
  if (auto err = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1); err)
  {
    return -1;
  }

  if (auto err = mbedtls_md_hmac_starts(&ctx, key.data(), key.size()); err)
  {
    return -2;
  }

  if (auto err = mbedtls_md_hmac_update(&ctx, msg.data(), msg.size()); err)
  {
    return -3;
  }

  if (auto err = mbedtls_md_hmac_finish(&ctx, md); err)
  {
    return -4;
  }

  return 0;
}