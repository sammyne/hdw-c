#include "api.h"

#include <string.h>

#include "curve.h"
#include "encoding.h"
#include "errors.h"
#include "hmac.h"
#include "math.h"

//using curve::Group;
//using curve::LEN_PUBKEY;
//using math::BigInt;

const uint32_t SEED_LEN_MIN = 16;
const uint32_t SEED_LEN_MAX = 64;
const uint32_t HARDENED_KEY_START = 0x80000000; // 2^31
const uint8_t MASTER_HMAC_KEY[] = "Bitcoin seed";

const int LEN_CHILD_INDEX = 4;

// bip32_harden_index 计算当前索引的加固索引。
int bip32_harden_index(uint32_t idx)
{
  return (idx | HARDENED_KEY_START);
}

// bip32_new_master_key 根据长度为 seed_len 的种子 seed 创建一个新的根私钥 priv。
int bip32_new_master_key(PrivKey *priv, const uint8_t *seed, uint32_t seed_len, CURVE curve)
{
  int err;
  uint8_t I[64];
  mbedtls_ecp_group grp;
  mbedtls_mpi d;

  err = hmac512(I, MASTER_HMAC_KEY, sizeof(MASTER_HMAC_KEY) - 1, seed, seed_len);
  if (err)
  {
    goto exit;
  }

  err = curve_new_group(&grp, curve);
  if (err)
  {
    goto exit;
  }

  err = curve_to_usable_api(&d, &grp, I);
  if (err)
  {
    goto exit;
  }

  err = curve_derive_compressed_public_key(priv->pub, &grp, &d);
  if (err)
  {
    goto exit;
  }

  memcpy(priv->priv, I, 32);
  memcpy(priv->chain_code, I + 32, 32);
  priv->depth = 0;
  priv->index = 0;
  priv->curve = curve;

exit:
  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&d);

  return err;
}

// bip32_privkey_child 派生 parent 索引为 idx 的链路上子私钥 child。
int bip32_privkey_child(PrivKey *child, const PrivKey *parent, uint32_t idx)
{
  int err;
  uint8_t data[LEN_PUBKEY + LEN_CHILD_INDEX];
  uint8_t I[64];
  mbedtls_ecp_group grp;
  mbedtls_mpi z, priv, child_priv;

  if (parent->depth == 255)
  {
    return ERR_DERIVE_TOO_DEEP;
  }

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

  err = hmac512(I, parent->chain_code, 32, data, LEN_PUBKEY + LEN_CHILD_INDEX);
  if (err)
  {
    goto exit;
  }

  err = curve_new_group(&grp, parent->curve);
  if (err)
  {
    goto exit;
  }

  err = curve_to_usable_api(&z, &grp, I);
  if (err)
  {
    goto exit;
  }

  err = math_big_int_new(&priv, parent->priv);
  if (err)
  {
    goto exit;
  }

  err = curve_add(&child_priv, &grp, &z, &priv);
  if (err)
  {
    goto exit;
  }

  err = math_big_int_serialize(child->priv, &child_priv);
  if (err)
  {
    goto exit;
  }

  child->curve = parent->curve;
  child->depth = parent->depth;
  child->index = idx;
  memcpy(child->chain_code, I + 32, 32);

  err = curve_derive_compressed_public_key(child->pub, &grp, &child_priv);
  if (err)
  {
    goto exit;
  }

exit:
  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&z);
  mbedtls_mpi_free(&priv);
  mbedtls_mpi_free(&child_priv);

  return err;
}

// bip32_privkey_deserialize 从 bip32_privkey_serialize 序列化的二进制数据还原私钥。
int bip32_privkey_deserialize(PrivKey *priv, const uint8_t buf[70])
{
  int err;
  int o = 0;
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  CURVE curve = (CURVE)(buf[o]);

  err = curve_new_group(&grp, curve);
  if (err)
  {
    goto exit;
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

  err = math_big_int_new(&d, priv->priv);
  if (err)
  {
    goto exit;
  }

  err = curve_derive_compressed_public_key(priv->pub, &grp, &d);
  if (err)
  {
    goto exit;
  }

exit:
  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&d);

  return err;
}

// bip32_privkey_serialize 序列化 priv 为二进制形式，以便于存储。
void bip32_privkey_serialize(uint8_t buf[70], const PrivKey *priv)
{
  int o = 0; // offset

  buf[o] = (uint8_t)(priv->curve);
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
