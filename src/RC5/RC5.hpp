#ifndef RC5_HPP
#define RC5_HPP
#include <array>
#include <cstdint>
#include <type_traits>
#include <vector>
#include <climits>


using Byte = uint8_t;
template <class Word> struct RC5Consts {
  static_assert(std::is_same<Word, std::uint16_t>::value ||
                    std::is_same<Word, std::uint32_t>::value ||
                    std::is_same<Word, std::uint64_t>::value,
                "Word can only be uint16_t, uint32_t, uint64_t");
  static const Word P;
  static const Word Q;
  static const Byte w = sizeof(Word) * CHAR_BIT;
  static const Byte u = (sizeof(Word) * CHAR_BIT) / 8;

};

template <> const std::uint16_t RC5Consts<std::uint16_t>::P = 0xB7E1;
template <> const std::uint16_t RC5Consts<std::uint16_t>::Q = 0x9E37;

template <> const std::uint32_t RC5Consts<std::uint32_t>::P = 0xB7E15163;
template <> const std::uint32_t RC5Consts<std::uint32_t>::Q = 0x9E3779B9;

template <> const std::uint64_t RC5Consts<std::uint64_t>::P = 0xB7E151628AED2A6B;
template <> const std::uint64_t RC5Consts<std::uint64_t>::Q = 0x9E3779B97F4A7C15;

template <class Word, Byte r, Byte b> class RC5 {
  struct TwoWords {
    Word A;
    Word B;
  };
  static const Byte c = std::max(1, b / RC5Consts<Word>::u);
  static std::array<Word, c> K;
public:
  void encrypt(const std::array<Byte, b> &K, const std::vector<Byte> &in,
               std::vector<Byte> &out) {
    ;
  }

private:
  TwoWords encrypt(TwoWords in);
};

#endif