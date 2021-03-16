#include <cstdint>
#include <iostream>

#include <mbedtls/md.h>

using namespace std;

// https://tls.mbed.org/api/md_8h.html#a1b858111212997b90bd7d2c71010a7ec
int main(int argc, char *argv[])
{
  const uint8_t key[] = "hello";
  const uint8_t msg[] = "world";
  const string expect = "6668ed2f7d016c5f12d7808fc4f2d1dc4851622d7f15616de947a823b3ee67d761b953f09560da301f832902020dd1c64f496df37eb7ac4fd2feeeb67d77ba9b";
  char buf[3];
  string got;

  mbedtls_md_context_t ctx;

  uint8_t md[64] = {0};

  if (auto err = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1); err)
  {
    printf("mbedtls_md_setup failed: %04x\n", err);
    goto exit;
  }

  if (auto err = mbedtls_md_hmac_starts(&ctx, key, sizeof(key) - 1); err)
  {
    printf("mbedtls_md_hmac_starts failed: %04x\n", err);
    goto exit;
  }

  if (auto err = mbedtls_md_hmac_update(&ctx, msg, sizeof(msg) - 1); err)
  {
    printf("mbedtls_md_hmac_update failed: %04x\n", err);
    goto exit;
  }

  if (auto err = mbedtls_md_hmac_finish(&ctx, md); err)
  {
    printf("mbedtls_md_hmac_finish failed: %04x\n", err);
    goto exit;
  }

  for (auto i = 0; i < sizeof(md); i++)
  {
    sprintf(buf, "%02x", md[i]);
    got += string(buf);
  }
  if (got != expect)
  {
    cout << "expect " << expect << endl;
    cout << "   got " << got << endl;
    goto exit;
  }

  cout << "ok :)" << endl;

exit:
  mbedtls_md_free(&ctx);

  return 0;
}