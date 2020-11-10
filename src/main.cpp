#include <RC5.hpp>
#include <ios>
#include <iostream>

int main(int argc, const char *argv[]) {
  auto rc5 = rc5::RC5_CBC<std::uint32_t, 8, 5,rc5::Type::Pad>({0x01, 0x02, 0x03, 0x04, 0x05}, {});
  std::vector<rc5::Byte> v;
  rc5.encrypt({0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff}, v);
  std::vector<rc5::Byte> v1;
  rc5.decrypt(v, v1);
}
