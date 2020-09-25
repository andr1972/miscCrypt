#pragma once
#include <stdint.h>
#include <string>
#include <vector>

namespace dcpcrypt {

char little_endian();
uint32_t LRot32(uint32_t a, uint32_t b);
uint32_t SwapDWord(uint32_t a);
void xorBlock(uint8_t *inData1, uint8_t  *inData2, uint32_t size);
std::vector<unsigned char> fromHex(std::string hexString);

uint32_t load32(const void* src);
uint64_t load64(const void* src);
void store16(void* dst, uint16_t w);
void store32(void* dst, uint32_t w);
void store64(void* dst, uint64_t w);
uint64_t load48(const void* src);
void store48(void* dst, uint64_t w);
uint32_t rotl32(const uint32_t w, const unsigned c);
uint64_t rotl64(const uint64_t w, const unsigned c);
uint32_t rotr32(const uint32_t w, const unsigned c);
uint64_t rotr64(const uint64_t w, const unsigned c);
void secure_zero_memory(void* v, size_t n);

#if defined(NATIVE_LITTLE_ENDIAN)
#define LOAD32(dest, src) memcpy(&(dest), (src), sizeof (dest))
#else
#define LOAD32(dest, src)                                          \
    do {                                                             \
    const uint8_t* load = (const uint8_t*)(src);                     \
    dest = ((uint64_t)(load[0]) <<  0) |                             \
           ((uint64_t)(load[1]) <<  8) |                             \
           ((uint64_t)(load[2]) << 16) |                             \
           ((uint64_t)(load[3]) << 24);                              \
    } while(0)
#endif

#define ROTR32(w, c) ((w) >> (c)) | ((w) << (32 - (c)))

}