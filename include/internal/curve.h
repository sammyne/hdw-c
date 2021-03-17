#pragma once

#include <mbedtls/ecp.h>

#include "api.h"
#include "math.h"

extern const int LEN_PUBKEY;

//std::pair<BigInt, int> add(const Group grp, const BigInt x, const BigInt y);
int curve_add(
    mbedtls_mpi *out, const mbedtls_ecp_group *grp, const mbedtls_mpi *x, const mbedtls_mpi *y);

//int derive_compressed_public_key(uint8_t out[LEN_PUBKEY], Group grp, const BigInt d);
int curve_derive_compressed_public_key(
    uint8_t out[LEN_PUBKEY], mbedtls_ecp_group *grp, const mbedtls_mpi *d);

//std::pair<Group, int> new_group(CURVE curve);
int curve_new_group(mbedtls_ecp_group *grp, CURVE curve);

//std::pair<BigInt, int> to_usable_api(Group grp, const uint8_t d[32]);
int curve_to_usable_api(mbedtls_mpi *out, mbedtls_ecp_group *grp, const uint8_t d[32]);
