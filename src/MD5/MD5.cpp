#include "MD5.hpp"
#include <climits>
#include <cassert>
#include <sstream>
#include <vector>
#include <iostream>
#include <limits>
#include <bitset>
using Chunk = std::array<std::uint32_t, 16>;// 512 bit
constexpr size_t CHUNK_SIZE = sizeof(Chunk::value_type) * 16;
constexpr auto BITS_CHUNK_SIZE = static_cast<std::uint64_t>(CHUNK_SIZE) * CHAR_BIT;
constexpr uint64_t BITS_SIZE_PART_SIZE = sizeof(uint64_t) * CHAR_BIT;
constexpr size_t BITS_CHUNK_PART_SIZE = sizeof(Chunk::value_type) * CHAR_BIT;


template <typename I> 
std::string toString(I val, size_t hexLen = sizeof(I)<<1) 
{
    static const char* digits = "0123456789ABCDEF";
    std::string result(hexLen,'0');
    for (size_t i=0, j=(hexLen-1)*4 ; i<hexLen; ++i,j-=4)
        result[i] = digits[(val>>j) & 0x0f];
    return result;
}

template <typename I, uint64_t binLen = sizeof(I) * CHAR_BIT> 
std::string toBinaryStr(I val)
{
    return std::bitset<binLen>(val).to_string();
}

std::string toString(const Chunk &chunk)
{
    std::string result;
    for(size_t i = 0; i < chunk.size() - 1; ++i)
        result += toString(chunk[i]) + " ";
    result += toString(chunk.back());
    return result;
}

std::uint32_t convert(const std::string &data, std::size_t begin)
{
    assert(begin < data.size());
    std::uint32_t value = 0;
    size_t i = begin, end = begin + 4;
    for (; i < end && i < data.size(); ++i)
    {
        value <<=CHAR_BIT;
        value += static_cast<std::uint32_t>(data[i]);
    }
    return value << (end - i) * CHAR_BIT;
}

std::vector<Chunk> toChunks(const std::string& data)
{
    std::vector<Chunk> result;
    for(size_t chunckBeginning = 0; chunckBeginning < data.size(); chunckBeginning += 64)
    {
        Chunk chunk = {};
        for (size_t index32Bit = 0, dataIndex = chunckBeginning;
            index32Bit < chunk.size() && dataIndex < data.size();
            index32Bit++)
        {
            chunk[index32Bit] = convert(data, dataIndex);
            dataIndex += sizeof(chunk[index32Bit]);
        }
        result.push_back(chunk);
    }
    if (result.empty())
        result.push_back(Chunk());
    return result;
}

void alignSizeTo448Mod512(std::vector<Chunk> &chunks, std::uint64_t bitsDataSize)
{
    if (bitsDataSize >= BITS_CHUNK_SIZE * chunks.size() - BITS_SIZE_PART_SIZE)
        chunks.push_back(Chunk());
}

Chunk::value_type revertBytes(Chunk::value_type value)
{
    auto selectByte = [] (Chunk::value_type val, size_t i)->Chunk::value_type 
    {
        size_t firstBit = i * CHAR_BIT;
        val = val << firstBit >> firstBit;
        size_t bitsToEnd = BITS_CHUNK_PART_SIZE - firstBit - CHAR_BIT;
        val = val >> bitsToEnd << bitsToEnd;
        return val;
    };  
    return selectByte(value, 0) >> (BITS_CHUNK_PART_SIZE - CHAR_BIT) | 
        selectByte(value, 1) >> CHAR_BIT |
        selectByte(value, 2) << CHAR_BIT |
        selectByte(value, 3) << (BITS_CHUNK_PART_SIZE - CHAR_BIT);
}

void insertLeadingBit(std::vector<Chunk> &chunks, std::uint64_t bitsDataSize)
{
    auto lastDataChunkIndex = bitsDataSize / BITS_CHUNK_SIZE;
    Chunk &lastDataChunk = chunks[lastDataChunkIndex];
    auto bitsDataSizeRest = (bitsDataSize % BITS_CHUNK_SIZE);
    auto &lastDataChunkPart = lastDataChunk[bitsDataSizeRest / BITS_CHUNK_PART_SIZE];
    bitsDataSizeRest %= BITS_CHUNK_PART_SIZE;
    lastDataChunkPart |= (1ul << (BITS_CHUNK_PART_SIZE - bitsDataSizeRest - 1));
}

void insertDataSize(std::vector<Chunk> &chunks, std::uint64_t bitsDataSize)
{
    auto &lastChunk = chunks.back();
    auto &lastChunkPart = lastChunk.back();
    lastChunkPart = revertBytes(bitsDataSize >> BITS_CHUNK_PART_SIZE);
    auto &penultimateChunkPart = lastChunk[lastChunk.size() - 2]; 
    penultimateChunkPart = revertBytes(bitsDataSize << BITS_CHUNK_PART_SIZE >> BITS_CHUNK_PART_SIZE);
}

Chunk::value_type leftRotate(Chunk::value_type value, size_t amount)
{
    assert(amount <= 31);
    Chunk::value_type mask = (1u << amount) - 1;
    Chunk::value_type left = value << amount;
    Chunk::value_type right = value >> (BITS_CHUNK_PART_SIZE - amount);
    return (left & ~mask) | (right & mask);
}

MD5Hash calculateMD5Hash(const std::vector<Chunk> &chunks)
{
    constexpr std::array<std::size_t, 64> s = {
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    };
    constexpr std::array<std::uint32_t, 64> K = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    MD5Hash hash = {
        0x67452301,// A
        0xefcdab89,// B
        0x98badcfe,// C
        0x10325476 // D
    };
    for (const auto& chunk : chunks)
    {
        MD5Hash tmpHash = hash;
        for (size_t i = 0; i < K.size(); ++i)
        {  
            MD5Hash::value_type F = 0;
            size_t g = 0;

            if (0 <= i && i <= 15)
            {
                F = (tmpHash[1] & tmpHash[2]) | (~tmpHash[1] & tmpHash[3]);
                g = i;
            }
            else if (16 <= i && i <= 31)
            {
                F = (tmpHash[3] & tmpHash[1]) | (~tmpHash[3] & tmpHash[2]);
                g = (5 * i + 1) % 16;
            }
            else if (32 <= i && i <= 47)
            {
                F = tmpHash[1] ^ tmpHash[2] ^ tmpHash[3];
                g = (3 * i + 5) % 16;
            }
            else if (48 <= i && i <= 63)
            {
                F = tmpHash[2] ^ (tmpHash[1] | (~tmpHash[3]));
                g = (7 * i) % 16;
            }
            F = (F + tmpHash[0] + K[i] + chunk[g]) & ~std::uint32_t(0);
            tmpHash[0] = tmpHash[3];
            tmpHash[3] = tmpHash[2];
            tmpHash[2] = tmpHash[1];
            tmpHash[1] = tmpHash[1] + leftRotate(F, s[i]);
        }
        for (size_t i = 0; i < hash.size(); ++i)
        {
            hash[i] += tmpHash[i];
        }
    }
    for (auto& val : hash)
        val = revertBytes(val);

    return hash;
}

void revertBytesInEachChunk(std::vector<Chunk>& chunks)
{
    for(auto &chunk: chunks)
        for(auto & word: chunk)
            word = revertBytes(word);
}

std::array<std::uint32_t, 4> generateMD5Hash(const std::string &data)
{
    static_assert(CHAR_BIT == 8, "generateMD5Hash requires byte to be 8 bit long");
    static_assert(sizeof(size_t) == 8 || sizeof(size_t) == 4, "generateMD5Hash requires size_t to be 8 or 4 bytes ");

    std::uint64_t bitsDataSize = static_cast<std::uint64_t>(data.size()) * sizeof(std::string::value_type) * CHAR_BIT;
    assert(bitsDataSize != std::numeric_limits<std::uint64_t>::max());
    auto chunks = toChunks(data);
    alignSizeTo448Mod512(chunks, bitsDataSize);
    insertLeadingBit(chunks, bitsDataSize);
    insertDataSize(chunks, bitsDataSize);
    revertBytesInEachChunk(chunks);
    return calculateMD5Hash(chunks);
}

std::string toString(const MD5Hash &hash)
{
    std::string result;
    for(size_t i = 0; i < hash.size(); ++i)
        result += toString(hash[i]);
    return result;
}