#include "curve.h"

namespace curve
{
  using std::pair;
  using std::shared_ptr;

  pair<BigInt, int> add(const Group grp, const BigInt x, const BigInt y)
  {
    auto [sum, _] = math::big_int_new();
    if (auto err = mbedtls_mpi_add_mpi(sum.get(), x.get(), y.get()); err)
    {
      return std::make_pair(sum, err);
    }

    auto [out, _2] = math::big_int_new();
    auto err = mbedtls_mpi_mod_mpi(out.get(), sum.get(), &(grp->N));

    return std::make_pair(out, err);
  }

  int derive_compressed_public_key(
      uint8_t out[LEN_PUBKEY], Group grp, const BigInt d)
  {
    auto D = new mbedtls_ecp_point;
    mbedtls_ecp_point_init(D);
    shared_ptr<mbedtls_ecp_point> _defer(D, [](auto *v) {
      mbedtls_ecp_point_free(v);
      delete v;
    });

    if (auto err = mbedtls_ecp_mul(grp.get(), D, d.get(), &(grp->G), nullptr, nullptr); err)
    {
      return err;
    }

    const auto FORMAT = MBEDTLS_ECP_PF_COMPRESSED;
    size_t olen = 0;

    if (auto err = mbedtls_ecp_point_write_binary(grp.get(), D, FORMAT, &olen, out, LEN_PUBKEY); err)
    {
      return err;
    }

    return 0;
  }

  pair<Group, int> new_group(CURVE curve)
  {
    auto grp = new mbedtls_ecp_group;
    mbedtls_ecp_group_init(grp);
    shared_ptr<mbedtls_ecp_group> out(grp, [](auto *v) {
      mbedtls_ecp_group_free(v);
      delete v;
    });

    auto grp_id = mbedtls_ecp_group_id::MBEDTLS_ECP_DP_NONE;
    switch (curve)
    {
    case CURVE::secp256k1:
      grp_id = mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256K1;
      break;
    case CURVE::secp256r1:
      grp_id = mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256R1;
      break;
    default:;
    }

    if (grp_id == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_NONE)
    {
      return std::make_pair(out, -1);
    }

    if (auto err = mbedtls_ecp_group_load(grp, grp_id); err)
    {
      return std::make_pair(out, -2);
    }

    return std::make_pair(out, 0);
  }

  pair<BigInt, int> to_usable_api(Group grp, const uint8_t d[32])
  {
    auto [out, err] = math::big_int_new(d);
    if (err)
    {
      return std::make_pair(out, err);
    }

    if (auto err = mbedtls_ecp_check_privkey(grp.get(), out.get()); err)
    {
      return std::make_pair(out, err);
    }

    return std::make_pair(out, 0);
  }
}