#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif
  enum CURVE
  {
    Unknown = 0,
    secp256k1,
    secp256r1,
  };

  // version isn't needed
  typedef struct
  {
    // @TODO: curve_type
    CURVE curve;
    uint8_t depth;          // 当前私钥的层次，根为 0，根的下一级为 1，依此类推，最大为 255
    uint32_t index;         // 当前父私钥派生当前私钥的路径索引
    uint8_t chain_code[32]; // 派生链路索引
    uint8_t priv[32];       // 私钥
    uint8_t pub[33];        // 对应私钥的公钥
  } PrivKey;

  // bip32_harden_index 计算当前索引的加固索引。
  int bip32_harden_index(uint32_t idx);

  // bip32_new_master_key 根据长度为 seed_len 的种子 seed 创建一个新的根私钥 priv。
  int bip32_new_master_key(
      PrivKey *priv, const uint8_t *seed, uint32_t seed_len, CURVE curve = secp256r1);

  // bip32_privkey_child 派生 parent 索引为 idx 的链路上子私钥 child。
  int bip32_privkey_child(PrivKey *child, const PrivKey *parent, uint32_t idx);

  // bip32_privkey_deserialize 从 bip32_privkey_serialize 序列化的二进制数据还原私钥。
  int bip32_privkey_deserialize(PrivKey *priv, const uint8_t buf[70]);

  // bip32_privkey_serialize 序列化 priv 为二进制形式，以便于存储。
  void bip32_privkey_serialize(uint8_t buf[70], const PrivKey *priv);

#ifdef __cplusplus
}
#endif