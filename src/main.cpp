#include <RC5.hpp>
#include <iostream>
#include <ios>
int main(int argc, const char *argv[]) {
  auto cr = RC5<std::uint32_t, 12, 16>(std::array<Byte, 16>())
                .encrypt(std::pair<std::uint32_t, std::uint32_t>(0, 0));
  std::cout << std::hex << cr.first << ' ' << cr.second;
}
