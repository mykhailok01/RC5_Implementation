#ifndef RC5_HPP
#define RC5_HPP
#include <array>
#include <climits>
#include <cstdint>
#include <type_traits>
#include <utility>
#include <vector>
#include <cassert>

namespace rc5 {
using Byte = uint8_t;

template <class Word> struct RC5Consts {
  static_assert(std::is_same<Word, std::uint16_t>::value ||
                    std::is_same<Word, std::uint32_t>::value ||
                    std::is_same<Word, std::uint64_t>::value,
                "Word can only be uint16_t, uint32_t or uint64_t");
  static const Word P;
  static const Word Q;
  static const Byte w = sizeof(Word) * CHAR_BIT;
  static const Byte u = (sizeof(Word) * CHAR_BIT) / 8;
};

template <> const std::uint16_t RC5Consts<std::uint16_t>::P = 0xB7E1;
template <> const std::uint16_t RC5Consts<std::uint16_t>::Q = 0x9E37;

template <> const std::uint32_t RC5Consts<std::uint32_t>::P = 0xB7E15163;
template <> const std::uint32_t RC5Consts<std::uint32_t>::Q = 0x9E3779B9;

template <>
const std::uint64_t RC5Consts<std::uint64_t>::P = 0xB7E151628AED2A6B;
template <>
const std::uint64_t RC5Consts<std::uint64_t>::Q = 0x9E3779B97F4A7C15;

template <class Word, Byte r, Byte b> class RC5 {
  static constexpr Byte c = std::max(1, b / RC5Consts<Word>::u);
  std::array<Word, c> L;

  static constexpr Byte t = 2 * (r + 1);
  std::array<Word, t> S;

public:
  static constexpr Byte BLOCK_SIZE = RC5Consts<Word>::u * 2;
  explicit RC5(const std::array<Byte, b> &K) : L{}, S{} {
    initL(K);
    initS();
    mixSL();
  }
  std::pair<Word, Word> encrypt(const std::pair<Word, Word> in) {
    Word A = in.first, B = in.second;
    A += S[0];
    B += S[1];
    for (Byte i = 1; i <= r; ++i) {
      A = leftRotate(A ^ B, B) + S[2 * i];
      B = leftRotate(B ^ A, A) + S[2 * i + 1];
    }
    return std::pair(A, B);
  }

  std::pair<Word, Word> decrypt(const std::pair<Word, Word> in) {
    Word A = in.first, B = in.second;
    for (Byte i = r; i >= 1; --i) {
      B = rightRotate(B - S[2 * i + 1], A) ^ A;
      A = rightRotate(A - S[2 * i], B) ^ B;
    }
    B -= S[1];
    A -= S[0];
    return std::pair(A, B);
  }

private:
  static Word leftRotate(Word x, Word y) {
    Byte w = RC5Consts<Word>::w;
    return (x << (y & (w - 1))) | (x >> (w - (y & (w - 1))));
  }
  static Word rightRotate(Word x, Word y) {
    Byte w = RC5Consts<Word>::w;
    return (x >> (y & (w - 1))) | (x << (w - (y & (w - 1))));
  }
  void initL(const std::array<Byte, b> &K) {
    if (b)
      for (Byte index = b; index > 0; --index) {
        Byte i = index - 1;
        L[i / RC5Consts<Word>::u] = (L[i / RC5Consts<Word>::u] << 8) + K[i];
      }
  }
  void initS() {
    S[0] = RC5Consts<Word>::P;
    for (Byte i = 1; i < t; i++)
      S[i] = S[i - 1] + RC5Consts<Word>::Q;
  }
  void mixSL() {
    Byte i = 0, j = 0;
    Word A = 0, B = 0;
    for (uint16_t iteration = 0, count = 3 * std::max(t, c); iteration < count;
         ++iteration) {
      A = S[i] = leftRotate(S[i] + A + B, 3);
      B = L[j] = leftRotate(L[j] + A + B, A + B);
      i = (i + 1) % t;
      j = (j + 1) % c;
    }
  }
};

enum class Type {
  NoPad,
  Pad
};

template <class Word, Byte r, Byte b, Type pad>
class RC5_CBC : private RC5<Word, r, b> {
public:
  using RC5<Word, r, b>::BLOCK_SIZE; // BB
private:
  using Block = std::array<Byte, BLOCK_SIZE>;
  const Block I;
  Block plainBlock;
  Block chainBlock;
  Byte plainBlockIndex;

public:
  explicit RC5_CBC(const std::array<Byte, b> &K,
                   const std::array<Byte, BLOCK_SIZE> I = {})
      : RC5<Word, r, b>(K), I(I), plainBlock{}, chainBlock(I),
        plainBlockIndex(0) {}

  void encrypt(const std::vector<Byte> &plainText,
                     std::vector<Byte> &encryptedText)
  {
    encryptUpdate(plainText, encryptedText);
    encryptFinal(encryptedText);
  }
  void decrypt(const std::vector<Byte> &encryptedText,
                     std::vector<Byte> &plainText) {
    assert(encryptedText.size() && !(encryptedText.size() % BLOCK_SIZE));
    decryptUpdate(encryptedText, plainText);
  }

private:
  std::pair<Word, Word> getLittleEndianWords(Block bytes) {
    Word A = 0, B = 0;
    for (Byte i = 0; i < BLOCK_SIZE / 2; ++i) {
      Byte shift = (1 << 3) * i;
      A += bytes[i] << shift;
    }
    for (Byte i = BLOCK_SIZE / 2; i < BLOCK_SIZE; ++i) {
      Byte shift = (1 << 3) * (i - BLOCK_SIZE / 2);
      B += bytes[i] << shift;
    }
    return {A, B};
  }
  Block getBlock(std::pair<Word, Word> in) {
    Word A = in.first, B = in.second;
    Block out{};
    for (Byte i = 0; i < BLOCK_SIZE / 2; ++i) {
      Byte shift = (1 << 3) * i;
      out[i] = (A >> shift) & 0xff;
    }
    for (Byte i = BLOCK_SIZE / 2; i < BLOCK_SIZE; ++i) {
      Byte shift = (1 << 3) * (i - BLOCK_SIZE / 2);
      out[i] = (B >> shift) & 0xff;
    }
    return out;
  }

  void blockEncrypt() {
    auto in = getLittleEndianWords(plainBlock);
    auto encrypted = RC5<Word, r, b>::encrypt(in);
    chainBlock = getBlock(encrypted);
  }

  void encryptUpdate(const std::vector<Byte> &plainText,
                     std::vector<Byte> &encryptedText) {
    using SizeT = std::vector<Byte>::size_type;
    SizeT N = plainText.size();
    SizeT plainIndex = 0;
    while (plainIndex < N) {
      if (plainBlockIndex < BLOCK_SIZE) {
        plainBlock[plainBlockIndex] = plainText[plainIndex];
        ++plainBlockIndex;
        ++plainIndex;
      }
      if (plainBlockIndex == BLOCK_SIZE) {
        plainBlockIndex = 0;
        for (Byte j = 0; j < BLOCK_SIZE; ++j)
          plainBlock[j] ^= chainBlock[j];
        blockEncrypt();
        for (Byte j = 0; j < BLOCK_SIZE; ++j)
          encryptedText.push_back(chainBlock[j]);
      }
    }
  }

  void encryptFinal(std::vector<Byte> &encryptedText) {
    assert(pad == Type::Pad || plainBlockIndex == 0);
    if (pad == Type::NoPad)
      return;
    Byte padLength = BLOCK_SIZE - plainBlockIndex;
    for( Byte j = 0; j < padLength; ++j){
      plainBlock[plainBlockIndex] = padLength;
      ++plainBlockIndex;
    }
    for (Byte j = 0; j < BLOCK_SIZE; ++j)
      plainBlock[j] ^= chainBlock[j];
    blockEncrypt();
    for (Byte j = 0; j < BLOCK_SIZE; ++j)
      encryptedText.push_back(chainBlock[j]);
  }

  void blockDecrypt() {
    auto in = getLittleEndianWords(chainBlock);
    auto plain = RC5<Word, r, b>::encrypt(in);
    chainBlock = getBlock(plain);
  }

  void decryptUpdate(const std::vector<Byte> &encryptedText,
                     std::vector<Byte> &plainText) {
    using SizeT = std::vector<Byte>::size_type;
    SizeT encryptedIndex = 0;
    Byte encryptedBlockIndex = 0;
    auto prevBlockChain = I;
    while (encryptedIndex < encryptedText.size()) {
      if (encryptedBlockIndex < BLOCK_SIZE) {
        chainBlock[encryptedBlockIndex] = encryptedText[encryptedIndex];
        ++encryptedBlockIndex;
        ++encryptedIndex;
      }
      if (encryptedBlockIndex == BLOCK_SIZE)
      {
        encryptedBlockIndex = 0;
        blockDecrypt();
        for (Byte j = 0; j < BLOCK_SIZE; ++j) {
          plainBlock[j] ^= prevBlockChain[j];
          plainText.push_back(plainBlock[j]);
        }
        prevBlockChain = chainBlock;
      }
    }
  }
};

} // namespace rc5

#endif