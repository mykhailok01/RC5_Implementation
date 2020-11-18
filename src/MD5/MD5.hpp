#ifndef MD5_HPP
#include <array>
#include <cstdint>
#include <string>

using MD5Hash = std::array<std::uint32_t, 4>;
MD5Hash generateMD5Hash(const std::string &data);
std::string toString(const MD5Hash &hash);

#endif