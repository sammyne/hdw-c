#include <cassert>
#include <cstring>
#include <iostream>

#include "api.h"

using namespace std;

int main()
{
  const int SEED_LEN = 64;
  const auto curve = CURVE::secp256k1;

  uint8_t seed[SEED_LEN];
  for (int i = 0; i < SEED_LEN; i++)
  {
    seed[i] = i;
  }

  PrivKey priv;
  if (auto err = bip32_new_master_key(&priv, seed, SEED_LEN, curve); err)
  {
    cout << "bip32_new_master_key failed: " << err << endl;
    return -1;
  }

  //auto priv_before = hexlify(priv.priv, 32);
  //auto pub_before = hexlify(priv.pub, 33);

  uint8_t buf[70];
  bip32_privkey_serialize(buf, &priv);

  PrivKey recovered;
  if (auto err = bip32_privkey_deserialize(&recovered, buf); err)
  {
    cout << "bip32_privkey_deserialize failed: " << err << endl;
    return -1;
  }

  assert(priv.curve == recovered.curve);
  assert(priv.depth == recovered.depth);
  assert(priv.index == recovered.index);
  assert(priv.curve == recovered.curve);

  assert(!memcmp(priv.chain_code, recovered.chain_code, 32));
  assert(!memcmp(priv.priv, recovered.priv, 32));
  assert(!memcmp(priv.pub, recovered.pub, 33));

  cout << "ok :)" << endl;

  return 0;
}
