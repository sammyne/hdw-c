#include "api.h"

#include <cstring>
#include <memory>

#include <mbedtls/ecp.h>

#include "encoding.h"
#include "errors.h"
#include "hmac.h"
#include "math.h"

using std::pair;
using std::shared_ptr;
using std::tuple;

using Group = shared_ptr<mbedtls_ecp_group>;

using math::BigInt;

const uint32_t SEED_LEN_MIN = 16;
const uint32_t SEED_LEN_MAX = 64;
const uint32_t HARDENED_KEY_START = 0x80000000; // 2^31
const uint8_t MASTER_HMAC_KEY[] = "Bitcoin seed";

const int LEN_CHILD_INDEX = 4;
const int LEN_PUBKEY = 33;

// forward declaration
pair<BigInt, int> curve_add(const Group grp, const BigInt x, const BigInt y);
int derive_compressed_public_key(uint8_t out[LEN_PUBKEY], Group grp, const BigInt d);
pair<Group, int> new_group(CURVE curve);
pair<BigInt, int> to_usable_api(Group grp, const uint8_t d[32]);

// bip32_harden_index 计算当前索引的加固索引。
int bip32_harden_index(uint32_t idx)
{
  return (idx | HARDENED_KEY_START);
}

// bip32_new_master_key 根据长度为 seed_len 的种子 seed 创建一个新的根私钥 priv。
int bip32_new_master_key(PrivKey *priv, const uint8_t *seed, uint32_t seed_len, CURVE curve)
{
  uint8_t I[64];
  {
    vector<uint8_t> key(MASTER_HMAC_KEY, MASTER_HMAC_KEY + sizeof(MASTER_HMAC_KEY) - 1);
    vector<uint8_t> _seed(seed, seed + seed_len);

    if (auto err = hmac512(I, key, _seed); err)
    {
      return err;
    }
  }

  if (auto [grp, err] = new_group(curve); err)
  {
    return err;
  }
  else if (auto [d, err] = to_usable_api(grp, I); err)
  {
    return err;
  }
  else if (auto err = derive_compressed_public_key(priv->pub, grp, d); err)
  {
    return err;
  }

  memcpy(priv->priv, I, 32);
  memcpy(priv->chain_code, I + 32, 32);
  priv->depth = 0;
  priv->index = 0;
  priv->curve = curve;

  return 0;
}

// bip32_privkey_child 派生 parent 索引为 idx 的链路上子私钥 child。
int bip32_privkey_child(PrivKey *child, const PrivKey *parent, uint32_t idx)
{
  if (parent->depth == 255)
  {
    return ERR_DERIVE_TOO_DEEP;
  }

  uint8_t data[LEN_PUBKEY + LEN_CHILD_INDEX];
  if (idx < HARDENED_KEY_START)
  {
    memcpy(data, parent->pub, LEN_PUBKEY);
  }
  else
  {
    data[0] = 0;
    mempcpy(data + 1, parent->priv, 32);
  }

  big_endian_put_uint32(data + LEN_PUBKEY, idx);

  uint8_t I[64];
  {
    // TODO: optimise memory copy
    // TODO: make chain code length constant
    vector<uint8_t> key(parent->chain_code, parent->chain_code + 32);
    vector<uint8_t> _data(data, data + LEN_PUBKEY + LEN_CHILD_INDEX);
    if (auto err = hmac512(I, key, _data); err)
    {
      return err;
    }
  }

  auto [grp, err] = new_group(parent->curve);
  if (err)
  {
    return err;
  }

  auto [z, err2] = to_usable_api(grp, I);
  if (err2)
  {
    return err2;
  }

  auto [d, err3] = math::big_int_new(parent->priv);
  if (err3)
  {
    return err3;
  }

  auto [dd, err4] = curve_add(grp, z, d);
  if (err4)
  {
    return err4;
  }
  else if (auto err = math::big_int_serialize(child->priv, dd); err)
  {
    return err;
  }

  child->curve = parent->curve;
  child->depth = parent->depth;
  child->index = idx;
  memcpy(child->chain_code, I + 32, 32);

  if (auto err = derive_compressed_public_key(child->pub, grp, dd); err)
  {
    return err;
  }

  return 0;
}

// bip32_privkey_deserialize 从 bip32_privkey_serialize 序列化的二进制数据还原私钥。
int bip32_privkey_deserialize(PrivKey *priv, const uint8_t buf[70])
{
  int o = 0;

  auto curve = CURVE(buf[o]);
  auto [grp, err] = new_group(curve);
  if (err)
  {
    return err;
  }
  priv->curve = curve;
  o++;

  priv->depth = buf[o];
  o++;

  priv->index = big_endian_uint32(buf + o);
  o += 4;

  memcpy(priv->chain_code, buf + o, 32);
  o += 32;

  memcpy(priv->priv, buf + o, 32);
  o += 32;

  auto [d, err2] = math::big_int_new(priv->priv);
  if (err2)
  {
    return err2;
  }

  return derive_compressed_public_key(priv->pub, grp, d);
}

// bip32_privkey_serialize 序列化 priv 为二进制形式，以便于存储。
void bip32_privkey_serialize(uint8_t buf[70], const PrivKey *priv)
{
  int o = 0; // offset

  buf[o] = uint8_t(priv->curve);
  o++;

  buf[o] = priv->depth;
  o++;

  big_endian_put_uint32(buf + o, priv->index);
  o += 4;

  memcpy(buf + o, priv->chain_code, 32);
  o += 32;

  memcpy(buf + o, priv->priv, 32);
  o += 32;
}

// internal

pair<BigInt, int> curve_add(const Group grp, const BigInt x, const BigInt y)
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