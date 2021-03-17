#pragma once

#include <stdint.h>

#include <mbedtls/bignum.h>

int math_big_int_new(mbedtls_mpi *out, const uint8_t d[32]);

int math_big_int_serialize(uint8_t out[32], const mbedtls_mpi *x);
