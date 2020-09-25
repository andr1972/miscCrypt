#include <stdint.h>
#include <vector>
#include "Util.h"

namespace dcpcrypt {

char little_endian()
{
	int num = 1;
	return *(char *)&num;
}

uint32_t LRot32(uint32_t a, uint32_t b)
{
	return (a << b) | (a >> (32 - b));
}

uint32_t SwapDWord(uint32_t a)
{
	return ((a & 0xFF) << 24) | ((a & 0xFF00) << 8) | ((a & 0xFF0000) >> 8) | ((a & 0xFF000000) >> 24);
}

void xorBlock(uint8_t *inData1, uint8_t  *inData2, uint32_t size)
{
	uint8_t *b1 = inData1;
	uint8_t *b2 = inData2;
	for (size_t i = 0; i < size; i++)
		b1[i] ^= b2[i];
}

int oneHexDigit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else throw "bad hex digit";
}

std::vector<unsigned char> fromHex(std::string hexString)
{
	std::vector<unsigned char> v;
	for (int i = 0; i < hexString.length(); i += 2)
	{
		char h_char = hexString[i];
		char l_char = hexString[i + 1];
		int b = oneHexDigit(h_char) * 16 + oneHexDigit(l_char);
		v.push_back(b);
	}
	return v;
}


/*
   BLAKE2 reference source code package - reference C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

uint32_t load32(const void* src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	uint32_t w;
	memcpy(&w, src, sizeof w);
	return w;
#else
	const uint8_t* p = (const uint8_t*)src;
	uint32_t w = *p++;
	w |= (uint32_t)(*p++) << 8;
	w |= (uint32_t)(*p++) << 16;
	w |= (uint32_t)(*p++) << 24;
	return w;
#endif
}

uint64_t load64(const void* src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	uint64_t w;
	memcpy(&w, src, sizeof w);
	return w;
#else
	const uint8_t* p = (const uint8_t*)src;
	uint64_t w = *p++;
	w |= (uint64_t)(*p++) << 8;
	w |= (uint64_t)(*p++) << 16;
	w |= (uint64_t)(*p++) << 24;
	w |= (uint64_t)(*p++) << 32;
	w |= (uint64_t)(*p++) << 40;
	w |= (uint64_t)(*p++) << 48;
	w |= (uint64_t)(*p++) << 56;
	return w;
#endif
}


/**
 * Stores w into dst
 *
 * @param      dst   the destination
 * @param[in]  w     word to be stored
 */
void store16(void* dst, uint16_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	memcpy(dst, &w, sizeof w);
#else
	uint8_t* p = (uint8_t*)dst;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w;
#endif
}

void store32(void* dst, uint32_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	memcpy(dst, &w, sizeof w);
#else
	uint8_t* p = (uint8_t*)dst;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w;
#endif
}

void store64(void* dst, uint64_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	memcpy(dst, &w, sizeof w);
#else
	uint8_t* p = (uint8_t*)dst;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w;
#endif
}

uint64_t load48(const void* src)
{
	const uint8_t* p = (const uint8_t*)src;
	uint64_t w = *p++;
	w |= (uint64_t)(*p++) << 8;
	w |= (uint64_t)(*p++) << 16;
	w |= (uint64_t)(*p++) << 24;
	w |= (uint64_t)(*p++) << 32;
	w |= (uint64_t)(*p++) << 40;
	return w;
}

void store48(void* dst, uint64_t w)
{
	uint8_t* p = (uint8_t*)dst;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w;
}

uint32_t rotl32(const uint32_t w, const unsigned c)
{
	return (w << c) | (w >> (32 - c));
}

uint64_t rotl64(const uint64_t w, const unsigned c)
{
	return (w << c) | (w >> (64 - c));
}

uint32_t rotr32(const uint32_t w, const unsigned c)
{
	return (w >> c) | (w << (32 - c));
}

uint64_t rotr64(const uint64_t w, const unsigned c)
{
	return (w >> c) | (w << (64 - c));
}

/* prevents compiler optimizing out memset() */
void secure_zero_memory(void* v, size_t n)
{
	volatile uint8_t* p = (volatile uint8_t*)v;
	while (n--)* p++ = 0;
}
}