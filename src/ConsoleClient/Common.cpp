#include "Common.hpp"
#include <MD5.hpp>
#include <Utility.hpp>
#include <iostream>
#include <cmath>

std::array<rc5::Byte, RC5Type::KEY_LENGTH> getRC5Key(const std::string &key) {
  MD5Hash hash = generateMD5Hash(key);
  std::array<rc5::Byte, RC5Type::KEY_LENGTH> rc5Key{}; 
  for (rc5::Byte i = 0; i < RC5Type::KEY_LENGTH; ++i) {
    rc5Key[i] = (hash[i / 4] >> 3 - i % 4) & 0xff;
  }
  return rc5Key;
}

rc5::Byte generate(uint32_t x) {
  uint32_t m = std::pow(2, 19) -1;
  uint32_t a = std::pow(6, 3);
  uint32_t c = 55;
  return (a * x + c) & m;
}
std::array<rc5::Byte, RC5Type::BLOCK_SIZE> getIV() {
  std::array<rc5::Byte, RC5Type::BLOCK_SIZE> result{};
  uint32_t x0 = 1024;
  uint32_t x = x0;
  for(auto &a : result) {
    a = x;
    x = generate(x);
  }
  return result;
}