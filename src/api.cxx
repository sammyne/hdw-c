#include "api.h"

#include <cstring>

#include "curve.h"
#include "encoding.h"
#include "errors.h"
#include "hmac.h"
#include "math.h"

using curve::Group;
using curve::LEN_PUBKEY;
using math::BigInt;

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
  uint8_t I[64];
  {
    vector<uint8_t> key(MASTER_HMAC_KEY, MASTER_HMAC_KEY + sizeof(MASTER_HMAC_KEY) - 1);
    vector<uint8_t> _seed(seed, seed + seed_len);

    if (auto err = hmac512(I, key, _seed); err)
    {
      return err;
    }
  }

  if (auto [grp, err] = curve::new_group(curve); err)
  {
    return err;
  }
  else if (auto [d, err] = curve::to_usable_api(grp, I); err)
  {
    return err;
  }
  else if (auto err = curve::derive_compressed_public_key(priv->pub, grp, d); err)
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

  auto [grp, err] = curve::new_group(parent->curve);
  if (err)
  {
    return err;
  }

  auto [z, err2] = curve::to_usable_api(grp, I);
  if (err2)
  {
    return err2;
  }

  auto [d, err3] = math::big_int_new(parent->priv);
  if (err3)
  {
    return err3;
  }

  auto [dd, err4] = curve::add(grp, z, d);
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

  if (auto err = curve::derive_compressed_public_key(child->pub, grp, dd); err)
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
  auto [grp, err] = curve::new_group(curve);
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

  return curve::derive_compressed_public_key(priv->pub, grp, d);
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
