#include "math.h"

namespace math
{
  using std::pair;

  pair<BigInt, int> big_int_new(const uint8_t d[32])
  {
    auto *n = new mbedtls_mpi;
    mbedtls_mpi_init(n);

    BigInt out(n, [](mbedtls_mpi *v) {
      mbedtls_mpi_free(v);
      delete v;
    });

    if (!d)
    {
      return std::make_pair(out, 0);
    }

    auto err = mbedtls_mpi_read_binary(out.get(), d, 32);

    return std::make_pair(out, err);
  }

  int big_int_serialize(uint8_t out[32], const BigInt &x)
  {
    return mbedtls_mpi_write_binary(x.get(), out, 32);
  }
}