#include "hdw/internal/curve.h"

const int LEN_PUBKEY = 33;

int curve_add(
    mbedtls_mpi *out, const mbedtls_ecp_group *grp, const mbedtls_mpi *x, const mbedtls_mpi *y)
{
  int err;
  mbedtls_mpi sum;

  err = math_big_int_new(&sum, NULL);
  if (err)
  {
    goto exit;
  }

  err = mbedtls_mpi_add_mpi(&sum, x, y);
  if (err)
  {
    goto exit;
  }

  err = math_big_int_new(out, NULL);
  if (err)
  {
    goto exit;
  }

  err = mbedtls_mpi_mod_mpi(out, &sum, &(grp->N));

exit:
  mbedtls_mpi_free(&sum);
  if (err)
  {
    mbedtls_mpi_free(out);
  }

  return err;
}

//int derive_compressed_public_key(
//    uint8_t out[LEN_PUBKEY], Group grp, const BigInt d)
int curve_derive_compressed_public_key(
    uint8_t out[LEN_PUBKEY], mbedtls_ecp_group *grp, const mbedtls_mpi *d)
{
  int err;
  mbedtls_ecp_point D;
  size_t olen;

  mbedtls_ecp_point_init(&D);
  err = mbedtls_ecp_mul(grp, &D, d, &(grp->G), NULL, NULL);
  if (err)
  {
    goto exit;
  }

  err = mbedtls_ecp_point_write_binary(
      grp, &D, MBEDTLS_ECP_PF_COMPRESSED, &olen, out, LEN_PUBKEY);
  if (err)
  {
    goto exit;
  }

exit:
  mbedtls_ecp_point_free(&D);

  return err;
}

//pair<Group, int> new_group(CURVE curve)
int curve_new_group(mbedtls_ecp_group *grp, CURVE curve)
{
  int err;
  mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_NONE;

  switch (curve)
  {
  case secp256k1:
    grp_id = MBEDTLS_ECP_DP_SECP256K1;
    break;
  case secp256r1:
    grp_id = MBEDTLS_ECP_DP_SECP256R1;
    break;
  default:;
  }

  if (grp_id == MBEDTLS_ECP_DP_NONE)
  {
    goto exit;
  }

  mbedtls_ecp_group_init(grp);
  err = mbedtls_ecp_group_load(grp, grp_id);
  if (err)
  {
    goto exit;
  }

exit:
  if (err)
  {
    mbedtls_ecp_group_free(grp);
  }

  return err;
}

//pair<BigInt, int> to_usable_api(Group grp, const uint8_t d[32])
int curve_to_usable_api(mbedtls_mpi *out, mbedtls_ecp_group *grp, const uint8_t d[32])
{
  int err;

  err = math_big_int_new(out, d);
  if (err)
  {
    goto exit;
  }

  err = mbedtls_ecp_check_privkey(grp, out);
  if (err)
  {
    goto exit;
  }

exit:
  if (err)
  {
    mbedtls_mpi_free(out);
  }

  return err;
}