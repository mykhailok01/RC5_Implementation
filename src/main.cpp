#include <RC5.hpp>
#include <ios>
#include <iostream>

int main(int argc, const char *argv[]) {
  auto rc5 = rc5::RC5_CBC<std::uint32_t, 0, 1, rc5::Type::NoPad>({0x00}, {});
  std::vector<rc5::Byte> result;
  rc5.encrypt(std::vector<rc5::Byte>(8, 0x00), result);
}
