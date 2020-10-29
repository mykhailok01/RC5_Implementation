#include <RC5.hpp>
int main(int argc, const char *argv[]) {
  std::vector<Byte> out;
  RC5<std::uint32_t, 12, 12>::encrypt(array<Byte, 12>(), std::vector<Byte>(), out);
}
