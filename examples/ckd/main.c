#include <stdio.h>

#include "hdw/api.h"

void hexlify(const uint8_t *buf, int buf_len);

// seed = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F ,len = 128
// privkey = DC8EA4CD4F576AAE3C4BD0D67F43512AEB1439871738ED3D6EC7ADB4A17362E6 ,len = 64
//  pubkey = 022226CE27C3991C0B828F38F250E1D7CFA7464CE1E63D5E10B05EC3665018FDC8 ,len = 66
// privkey-123 = B9E0BE819DE8047AFD5557EB7F67B68DF0CDC84FE1C2A60B4B12D789CB77475E ,len = 64
// dc, 8e
int main()
{
  const int SEED_LEN = 64;
  const CURVE curve = secp256k1;
  uint8_t seed[SEED_LEN];
  PrivKey priv;
  int err;

  for (int i = 0; i < SEED_LEN; i++)
  {
    seed[i] = i;
  }
  hexlify(seed, SEED_LEN);

  err = bip32_new_master_key(&priv, seed, SEED_LEN, curve);
  if (err)
  {
    printf("bip32_new_master_key failed: %d\n", err);
    return -1;
  }

  printf("master private key = ");
  hexlify(priv.priv, 32);

  return 0;
}

void hexlify(const uint8_t *buf, int buf_len)
{
  for (int i = 0; i < buf_len; i++)
  {
    printf("%02x", buf[i]);
  }
  printf("\n");
}