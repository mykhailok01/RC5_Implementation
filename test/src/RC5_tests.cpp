#include "gtest/gtest.h"
#include <RC5.hpp>
#include <Utility.hpp>
#include <algorithm>
#include <functional>
#include <iostream>
#include <optional>

using namespace rc5;
template <class Word, Byte r, Byte b> class RC5Test : public ::testing::Test {
public:
  using RC5T = RC5<Word, r, b>;

protected:
  void SetUp() override{};
  void TearDown() override{};
  virtual void
  verify(std::pair<Word, Word> in, std::array<Byte, b> K,
         std::optional<std::pair<Word, Word>> expected = std::nullopt) {
    auto rc5 = RC5T(K);
    auto encrypted = rc5.encrypt(in);
    if (expected)
      EXPECT_EQ(encrypted, expected.value());
    auto decrypted = rc5.decrypt(encrypted);
    EXPECT_EQ(in, decrypted);
  }
};

using RC5_32_12_16Test = RC5Test<std::uint32_t, 12, 16>;
TEST_F(RC5_32_12_16Test, AllZero) { verify({0, 0}, {}, std::pair{0xeedba521, 0x6d8f4b15}); }
TEST_F(RC5_32_12_16Test, 0fff_0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f) {
  verify({0x0f, 0xff}, {0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
                        0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f});
}

using RC5_32_8_5Test = RC5Test<std::uint32_t, 5, 8>;
TEST_F(RC5_32_8_5Test, WithKey) {
  verify({0xffffffff, 0xffffffff}, {0x01, 0x02, 0x03, 0x04, 0x05}, std::pair{0x7875dbf6,0x738c6478});
}

template <class Container> class ToHexStringTest : public ::testing::Test {
protected:
  void SetUp() override{};
  void TearDown() override{};
  virtual void verify(Container c, std::string expected) {
    std::string actual = toHexString(c);
    EXPECT_EQ(actual, expected);
  }
};

using ByteVectorToHexStringTest = ToHexStringTest<std::vector<Byte>>;
TEST_F(ByteVectorToHexStringTest, AllZero) {
  verify(std::vector<Byte>(4, 0x00), "00000000");
}

using ByteArrayToHexStringTest = ToHexStringTest<std::array<Byte, 4>>;
TEST_F(ByteArrayToHexStringTest, AllZero) {
  verify(std::array<Byte, 4>{}, "00000000");
}

bool operator==(const std::vector<Byte> &first,
                const std::vector<Byte> &second) {
  return std::equal(first.cbegin(), first.cend(), second.cbegin(),
                    second.cend());
}

template <class Word, Byte r, Byte b, Type pad>
class RC5CBCTest : public ::testing::Test {
protected:
  void SetUp() override {}
  void TearDown() override {}

  static constexpr Byte BLOCK_SIZE = RC5_CBC<Word, r, b, pad>::BLOCK_SIZE;
  void verify(std::array<Byte, b> key, std::array<Byte, BLOCK_SIZE> iv,
              const std::vector<Byte> &input,
              const std::optional<const std::vector<Byte>> expected) {
    auto algorithm = rc5(key, iv);
    std::vector<Byte> encrypted;
    algorithm.encrypt(input, encrypted);
    if (expected)
      EXPECT_EQ(encrypted, expected.value());
    std::vector<Byte> plain;
    algorithm.decrypt(encrypted, plain);
    EXPECT_EQ(plain, input);
  }
  auto rc5(const std::array<Byte, b> K,
           const std::array<Byte, BLOCK_SIZE> I = {}) const {
    return RC5_CBC<Word, r, b, pad>(K, I);
  }
};

using RC5CBC_32_0_1Test = RC5CBCTest<std::uint32_t, 0, 1, Type::NoPad>;
TEST_F(RC5CBC_32_0_1Test, ZeroOnly) {
  verify({0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
         std::vector<Byte>(8, 0x00),
         std::vector<Byte>{0x7a, 0x7b, 0xba, 0x4d, 0x79, 0x11, 0x1d, 0x1e});
}
TEST_F(RC5CBC_32_0_1Test, InputFF) {
  verify({0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
         std::vector<Byte>(8, 0xff),
         std::vector<Byte>{0x79, 0x7b, 0xba, 0x4d, 0x78, 0x11, 0x1d, 0x1e});
}
TEST_F(RC5CBC_32_0_1Test, IVHas1AtTheEnd) {
  verify({0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
         std::vector<Byte>(8, 0x00),
         std::vector<Byte>{0x7a, 0x7b, 0xba, 0x4d, 0x79, 0x11, 0x1d, 0x1f});
}

using RC5CBC_32_8_5Test = RC5CBCTest<std::uint32_t, 8, 5, Type::NoPad>;
TEST_F(RC5CBC_32_8_5Test, PAllFF) {
  verify({0x01, 0x02, 0x03, 0x04, 0x05}, {}, std::vector<Byte>(8, 0xff),
         std::vector<Byte>{0x78, 0x75, 0xdb, 0xf6, 0x73, 0x8c, 0x64, 0x78});
}

using RC5CBCPad_32_8_5Test = RC5CBCTest<std::uint32_t, 8, 5, Type::Pad>;
TEST_F(RC5CBCPad_32_8_5Test, PAllFF) {
  verify({0x01, 0x02, 0x03, 0x04, 0x05}, {}, std::vector<Byte>(8, 0xff),
         std::vector<Byte>{0x78, 0x75, 0xdb, 0xf6, 0x73, 0x8c, 0x64, 0x78, 0x8f,
                           0x34, 0xc3, 0xc6, 0x81, 0xc9, 0x96, 0x95});
}
