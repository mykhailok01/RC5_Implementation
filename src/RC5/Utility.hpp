#ifndef UTILITY_HPP
#define UTILITY_HPP
#include "RC5.hpp"

namespace rc5 {
template <class I>
std::string toHexString(I val) {
  static constexpr size_t hexLen = sizeof(I) << 1;
  static const char *digits = "0123456789ABCDEF";
  std::string result(hexLen, '0');
  for (size_t i = 0, j = (hexLen - 1) * 4; i < hexLen; ++i, j -= 4)
    result[i] = digits[(val >> j) & 0x0f];
  return result;
}
template<class Itr>
std::string toHexString(Itr begin, Itr end) {
  std::string result;
  for (;begin != end; ++begin)
    result += toHexString(*begin);
  return result;
}
template <> std::string toHexString(std::vector<Byte> v) {
  return toHexString(v.cbegin(), v.cend());
}
template <std::size_t N> std::string toHexString(std::array<Byte, N> a) {
  return toHexString(a.cbegin(), a.cend());
}
} // namespace rc5

#endif