#ifndef RC5_HPP
#include <cstdint>
#include <type_traits>
#include <array>

template<class Word, uint8_t r, uint8_t b>
class RC5
{
    static_assert(std::is_same<Word, uint16_t>::value || std::is_same<Word, uint32_t>::value || std::is_same<Word, uint64_t>::value,
        "Word can only be uint16_t, uint32_t, uint64_t");
public:

private:
    static Word P;
    static Word Q;
};

#endif