#pragma once

#include <cstdint>
#include <memory>

#include <mbedtls/bignum.h>

namespace math
{
  using BigInt = std::shared_ptr<mbedtls_mpi>;

  std::pair<BigInt, int> big_int_new(const uint8_t d[32] = nullptr);

  int big_int_serialize(uint8_t out[32], const BigInt &x);
}