#include "gtest/gtest.h"
#include <RC5.hpp>
#include <Utility.hpp>
#include <iostream>

using namespace rc5;
template <class Word, Byte r, Byte b>
class RC5EncryptDecryptTest : public ::testing::Test {
public:
  using RC5T = RC5<Word, r, b>;

protected:
  void SetUp() override{};
  void TearDown() override{};
  virtual void verify(std::pair<Word, Word> in, std::array<Byte, b> K) {
    auto rc5 = RC5T(K);
    auto encrypted = rc5.encrypt(in);
    auto decrypted = rc5.decrypt(encrypted);
    EXPECT_EQ(in, decrypted);
  }
};
using RC5_32_12_16EncryptDecryptTest =
    RC5EncryptDecryptTest<std::uint32_t, 12, 16>;

TEST_F(RC5_32_12_16EncryptDecryptTest, AllZero) { verify({0, 0}, {}); }

TEST_F(RC5_32_12_16EncryptDecryptTest, 0fff_0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f) {
  verify({0x0f, 0xff}, {0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
                        0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f});
}

TEST_F(RC5_32_12_16EncryptDecryptTest, AllZeroOnlyEncrypt) {
  auto rc5 = RC5_32_12_16EncryptDecryptTest::RC5T({});
  auto actual_out = rc5.encrypt({0, 0});
  auto expected_out =
      std::pair<std::uint32_t, std::uint32_t>{0xeedba521, 0x6d8f4b15};
  EXPECT_EQ(actual_out, expected_out);
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

template <class Word, Byte r, Byte b>
class RC5CBCEncryptDecryptTest : public ::testing::Test {
public:
  using RC5_CBCT = RC5_CBC<Word, r, b, Type::NoPad>;

protected:
  void SetUp() override{};
  void TearDown() override{};
};

using RC5CBC_32_0_1EncryptDecryptTest =
    RC5CBCEncryptDecryptTest<std::uint32_t, 0, 1>;
TEST_F(RC5CBC_32_0_1EncryptDecryptTest, AllZeroOnlyEncrypt) {
  auto rc5 = RC5CBC_32_0_1EncryptDecryptTest::RC5_CBCT({0x00}, {});
  std::vector<Byte> result;
  rc5.encrypt(std::vector<Byte>(8, 0x00), result);
  EXPECT_EQ(toHexString(result), "7A7BBA4D79111D1E");
}


