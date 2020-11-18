#ifndef COMMON_HPP
#define COMMON_HPP
#include <RC5.hpp>
#include <string>
using RC5Type = rc5::RC5_CBC<std::uint16_t, 12, 16, rc5::Type::Pad>;
std::array<rc5::Byte, RC5Type::KEY_LENGTH> getRC5Key(const std::string &password);
std::array<rc5::Byte, RC5Type::BLOCK_SIZE> getIV();
#endif