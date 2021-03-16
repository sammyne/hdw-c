#pragma once

#include <cstdint>
#include <vector>

using std::vector;

int hmac512(uint8_t md[64], const vector<uint8_t> &key, const vector<uint8_t> &msg);
