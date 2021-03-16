#pragma once

#include <mbedtls/ecp.h>

#include "api.h"
#include "math.h"

namespace curve
{
  using Group = std::shared_ptr<mbedtls_ecp_group>;
  using math::BigInt;

  const int LEN_PUBKEY = 33;

  std::pair<BigInt, int> add(const Group grp, const BigInt x, const BigInt y);

  int derive_compressed_public_key(uint8_t out[LEN_PUBKEY], Group grp, const BigInt d);

  std::pair<Group, int> new_group(CURVE curve);

  std::pair<BigInt, int> to_usable_api(Group grp, const uint8_t d[32]);

}