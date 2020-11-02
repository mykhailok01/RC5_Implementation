#include <RC5.hpp>
#include <ios>
#include <iostream>

int main(int argc, const char *argv[]) {
  auto key = std::array<Byte, 16>{};
  auto rc5_32_12_16 = RC5<std::uint32_t, 12, 16>(key);
  auto cr = rc5_32_12_16.encrypt({0, 0});
  cr = rc5_32_12_16.decrypt(cr);

  std::cout << std::hex << cr.first << ' ' << cr.second;
}
