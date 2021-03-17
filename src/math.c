#include "math.h"

//pair<BigInt, int> big_int_new(const uint8_t d[32])
int math_big_int_new(mbedtls_mpi *out, const uint8_t d[32])
{
  int err;

  mbedtls_mpi_init(out);

  if (!d)
  {
    return 0;
  }

  err = mbedtls_mpi_read_binary(out, d, 32);
  if (err)
  {
    mbedtls_mpi_free(out);
    return -1;
  }

  return 0;
}

//int big_int_serialize(uint8_t out[32], const BigInt &x)
int math_big_int_serialize(uint8_t out[32], const mbedtls_mpi *x)
{
  return mbedtls_mpi_write_binary(x, out, 32);
}