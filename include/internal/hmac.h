#pragma once

#include <stdint.h>

int hmac512(
    uint8_t md[64], const uint8_t *key, int key_len, const uint8_t *data, int data_len);
