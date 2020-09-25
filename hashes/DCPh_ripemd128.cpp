#include "DCPh_ripemd128.h"
#include "Util.h"
#include "Exception.h"

using namespace dcpcrypt;

DCPh_ripemd128::DCPh_ripemd128()
{
}


DCPh_ripemd128::~DCPh_ripemd128()
{
}

std::string DCPh_ripemd128::getAlgorithm()
{
	return "ripemd-128";
}

int DCPh_ripemd128::getHashSize()
{
	return 128;
}

bool DCPh_ripemd128::selfTest()
{
	const uint8_t Test1Out[16] = { 0x86,0xbe,0x7a,0xfa,0x33,0x9d,0x0f,0xc7,0xcf,0xc7,0x85,0xe7,0x2f,0x57,0x8d,0x33 };
	const uint8_t Test2Out[16] = { 0xfd,0x2a,0xa6,0x07,0xf7,0x1d,0xc8,0xf5,0x10,0x71,0x49,0x22,0xb3,0x71,0x83,0x4e };
	uint8_t TestOut[16];
	init();
	updateStr("a");
	final(TestOut);
	bool result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
	init();
	updateStr("abcdefghijklmnopqrstuvwxyz");
	final(TestOut);
	result = memcmp(TestOut, Test2Out, sizeof(Test2Out)) == 0 && result;
	return result;
}

void DCPh_ripemd128::init()
{
	burn();
	CurrentHash[0] = 0x67452301;
	CurrentHash[1] = 0xefcdab89;
	CurrentHash[2] = 0x98badcfe;
	CurrentHash[3] = 0x10325476;
	fInitialized = true;
}

void DCPh_ripemd128::burn()
{
	lenHi = 0; lenLo = 0;
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
	memset(CurrentHash, 0, sizeof(CurrentHash));
	fInitialized = false;
}

void DCPh_ripemd128::update(const unsigned char *buffer, uint32_t size)
{
	if (!fInitialized)
		throw EDCP_hash("Hash not initialized");

	lenHi += size >> 29;
	lenLo += size * 8;
	if (lenLo < size * 8)
		lenHi++;

	const unsigned char *PBuf = buffer;
	while (size > 0)
	{
		if (sizeof(HashBuffer) - index <= uint32_t(size))
		{
			memmove(HashBuffer + index, PBuf, sizeof(HashBuffer) - index);
			size -= sizeof(HashBuffer) - index;
			PBuf += sizeof(HashBuffer) - index;
			compress();
		}
		else
		{
			memmove(HashBuffer + index, PBuf, size);
			index += size;
			size = 0;
		}
	}
}


void DCPh_ripemd128::final(uint8_t * digest)
{
	if (!fInitialized)
		throw EDCP_hash("Hash not initialized");
	HashBuffer[index] = 0x80;
	if (index >= 56)
		compress();
	*((uint32_t*)(HashBuffer + 56)) = lenLo;
	*((uint32_t*)(HashBuffer + 60)) = lenHi;
	compress();
	memmove(digest, CurrentHash, sizeof(CurrentHash));
	burn();
}


void DCPh_ripemd128::compress()
{
	uint32_t X[16];
	uint32_t a, aa, b, bb, c, cc, d, dd, t;
	memset(X, 0, sizeof(X));
	memmove(X, HashBuffer, sizeof(X));
	a = CurrentHash[0]; aa = a;
	b = CurrentHash[1]; bb = b;
	c = CurrentHash[2]; cc = c;
	d = CurrentHash[3]; dd = d;

	t = a + (b ^ c ^ d) + X[0]; a = (t << 11) | (t >> (32 - 11));
	t = d + (a ^ b ^ c) + X[1]; d = (t << 14) | (t >> (32 - 14));
	t = c + (d ^ a ^ b) + X[2]; c = (t << 15) | (t >> (32 - 15));
	t = b + (c ^ d ^ a) + X[3]; b = (t << 12) | (t >> (32 - 12));
	t = a + (b ^ c ^ d) + X[4]; a = (t << 5) | (t >> (32 - 5));
	t = d + (a ^ b ^ c) + X[5]; d = (t << 8) | (t >> (32 - 8));
	t = c + (d ^ a ^ b) + X[6]; c = (t << 7) | (t >> (32 - 7));
	t = b + (c ^ d ^ a) + X[7]; b = (t << 9) | (t >> (32 - 9));
	t = a + (b ^ c ^ d) + X[8]; a = (t << 11) | (t >> (32 - 11));
	t = d + (a ^ b ^ c) + X[9]; d = (t << 13) | (t >> (32 - 13));
	t = c + (d ^ a ^ b) + X[10]; c = (t << 14) | (t >> (32 - 14));
	t = b + (c ^ d ^ a) + X[11]; b = (t << 15) | (t >> (32 - 15));
	t = a + (b ^ c ^ d) + X[12]; a = (t << 6) | (t >> (32 - 6));
	t = d + (a ^ b ^ c) + X[13]; d = (t << 7) | (t >> (32 - 7));
	t = c + (d ^ a ^ b) + X[14]; c = (t << 9) | (t >> (32 - 9));
	t = b + (c ^ d ^ a) + X[15]; b = (t << 8) | (t >> (32 - 8));

	t = a + ((b & c) | (~b & d)) + X[7] + 0x5A827999; a = (t << 7) | (t >> (32 - 7));
	t = d + ((a & b) | (~a & c)) + X[4] + 0x5A827999; d = (t << 6) | (t >> (32 - 6));
	t = c + ((d & a) | (~d & b)) + X[13] + 0x5A827999; c = (t << 8) | (t >> (32 - 8));
	t = b + ((c & d) | (~c & a)) + X[1] + 0x5A827999; b = (t << 13) | (t >> (32 - 13));
	t = a + ((b & c) | (~b & d)) + X[10] + 0x5A827999; a = (t << 11) | (t >> (32 - 11));
	t = d + ((a & b) | (~a & c)) + X[6] + 0x5A827999; d = (t << 9) | (t >> (32 - 9));
	t = c + ((d & a) | (~d & b)) + X[15] + 0x5A827999; c = (t << 7) | (t >> (32 - 7));
	t = b + ((c & d) | (~c & a)) + X[3] + 0x5A827999; b = (t << 15) | (t >> (32 - 15));
	t = a + ((b & c) | (~b & d)) + X[12] + 0x5A827999; a = (t << 7) | (t >> (32 - 7));
	t = d + ((a & b) | (~a & c)) + X[0] + 0x5A827999; d = (t << 12) | (t >> (32 - 12));
	t = c + ((d & a) | (~d & b)) + X[9] + 0x5A827999; c = (t << 15) | (t >> (32 - 15));
	t = b + ((c & d) | (~c & a)) + X[5] + 0x5A827999; b = (t << 9) | (t >> (32 - 9));
	t = a + ((b & c) | (~b & d)) + X[2] + 0x5A827999; a = (t << 11) | (t >> (32 - 11));
	t = d + ((a & b) | (~a & c)) + X[14] + 0x5A827999; d = (t << 7) | (t >> (32 - 7));
	t = c + ((d & a) | (~d & b)) + X[11] + 0x5A827999; c = (t << 13) | (t >> (32 - 13));
	t = b + ((c & d) | (~c & a)) + X[8] + 0x5A827999; b = (t << 12) | (t >> (32 - 12));

	t = a + ((b | ~c) ^ d) + X[3] + 0x6ED9EBA1; a = (t << 11) | (t >> (32 - 11));
	t = d + ((a | ~b) ^ c) + X[10] + 0x6ED9EBA1; d = (t << 13) | (t >> (32 - 13));
	t = c + ((d | ~a) ^ b) + X[14] + 0x6ED9EBA1; c = (t << 6) | (t >> (32 - 6));
	t = b + ((c | ~d) ^ a) + X[4] + 0x6ED9EBA1; b = (t << 7) | (t >> (32 - 7));
	t = a + ((b | ~c) ^ d) + X[9] + 0x6ED9EBA1; a = (t << 14) | (t >> (32 - 14));
	t = d + ((a | ~b) ^ c) + X[15] + 0x6ED9EBA1; d = (t << 9) | (t >> (32 - 9));
	t = c + ((d | ~a) ^ b) + X[8] + 0x6ED9EBA1; c = (t << 13) | (t >> (32 - 13));
	t = b + ((c | ~d) ^ a) + X[1] + 0x6ED9EBA1; b = (t << 15) | (t >> (32 - 15));
	t = a + ((b | ~c) ^ d) + X[2] + 0x6ED9EBA1; a = (t << 14) | (t >> (32 - 14));
	t = d + ((a | ~b) ^ c) + X[7] + 0x6ED9EBA1; d = (t << 8) | (t >> (32 - 8));
	t = c + ((d | ~a) ^ b) + X[0] + 0x6ED9EBA1; c = (t << 13) | (t >> (32 - 13));
	t = b + ((c | ~d) ^ a) + X[6] + 0x6ED9EBA1; b = (t << 6) | (t >> (32 - 6));
	t = a + ((b | ~c) ^ d) + X[13] + 0x6ED9EBA1; a = (t << 5) | (t >> (32 - 5));
	t = d + ((a | ~b) ^ c) + X[11] + 0x6ED9EBA1; d = (t << 12) | (t >> (32 - 12));
	t = c + ((d | ~a) ^ b) + X[5] + 0x6ED9EBA1; c = (t << 7) | (t >> (32 - 7));
	t = b + ((c | ~d) ^ a) + X[12] + 0x6ED9EBA1; b = (t << 5) | (t >> (32 - 5));

	t = a + ((b & d) | (c & ~d)) + X[1] + 0x8F1BBCDC; a = (t << 11) | (t >> (32 - 11));
	t = d + ((a & c) | (b & ~c)) + X[9] + 0x8F1BBCDC; d = (t << 12) | (t >> (32 - 12));
	t = c + ((d & b) | (a & ~b)) + X[11] + 0x8F1BBCDC; c = (t << 14) | (t >> (32 - 14));
	t = b + ((c & a) | (d & ~a)) + X[10] + 0x8F1BBCDC; b = (t << 15) | (t >> (32 - 15));
	t = a + ((b & d) | (c & ~d)) + X[0] + 0x8F1BBCDC; a = (t << 14) | (t >> (32 - 14));
	t = d + ((a & c) | (b & ~c)) + X[8] + 0x8F1BBCDC; d = (t << 15) | (t >> (32 - 15));
	t = c + ((d & b) | (a & ~b)) + X[12] + 0x8F1BBCDC; c = (t << 9) | (t >> (32 - 9));
	t = b + ((c & a) | (d & ~a)) + X[4] + 0x8F1BBCDC; b = (t << 8) | (t >> (32 - 8));
	t = a + ((b & d) | (c & ~d)) + X[13] + 0x8F1BBCDC; a = (t << 9) | (t >> (32 - 9));
	t = d + ((a & c) | (b & ~c)) + X[3] + 0x8F1BBCDC; d = (t << 14) | (t >> (32 - 14));
	t = c + ((d & b) | (a & ~b)) + X[7] + 0x8F1BBCDC; c = (t << 5) | (t >> (32 - 5));
	t = b + ((c & a) | (d & ~a)) + X[15] + 0x8F1BBCDC; b = (t << 6) | (t >> (32 - 6));
	t = a + ((b & d) | (c & ~d)) + X[14] + 0x8F1BBCDC; a = (t << 8) | (t >> (32 - 8));
	t = d + ((a & c) | (b & ~c)) + X[5] + 0x8F1BBCDC; d = (t << 6) | (t >> (32 - 6));
	t = c + ((d & b) | (a & ~b)) + X[6] + 0x8F1BBCDC; c = (t << 5) | (t >> (32 - 5));
	t = b + ((c & a) | (d & ~a)) + X[2] + 0x8F1BBCDC; b = (t << 12) | (t >> (32 - 12));

	t = aa + ((bb & dd) | (cc & ~dd)) + X[5] + 0x50A28BE6; aa = (t << 8) | (t >> (32 - 8));
	t = dd + ((aa & cc) | (bb & ~cc)) + X[14] + 0x50A28BE6; dd = (t << 9) | (t >> (32 - 9));
	t = cc + ((dd & bb) | (aa & ~bb)) + X[7] + 0x50A28BE6; cc = (t << 9) | (t >> (32 - 9));
	t = bb + ((cc & aa) | (dd & ~aa)) + X[0] + 0x50A28BE6; bb = (t << 11) | (t >> (32 - 11));
	t = aa + ((bb & dd) | (cc & ~dd)) + X[9] + 0x50A28BE6; aa = (t << 13) | (t >> (32 - 13));
	t = dd + ((aa & cc) | (bb & ~cc)) + X[2] + 0x50A28BE6; dd = (t << 15) | (t >> (32 - 15));
	t = cc + ((dd & bb) | (aa & ~bb)) + X[11] + 0x50A28BE6; cc = (t << 15) | (t >> (32 - 15));
	t = bb + ((cc & aa) | (dd & ~aa)) + X[4] + 0x50A28BE6; bb = (t << 5) | (t >> (32 - 5));
	t = aa + ((bb & dd) | (cc & ~dd)) + X[13] + 0x50A28BE6; aa = (t << 7) | (t >> (32 - 7));
	t = dd + ((aa & cc) | (bb & ~cc)) + X[6] + 0x50A28BE6; dd = (t << 7) | (t >> (32 - 7));
	t = cc + ((dd & bb) | (aa & ~bb)) + X[15] + 0x50A28BE6; cc = (t << 8) | (t >> (32 - 8));
	t = bb + ((cc & aa) | (dd & ~aa)) + X[8] + 0x50A28BE6; bb = (t << 11) | (t >> (32 - 11));
	t = aa + ((bb & dd) | (cc & ~dd)) + X[1] + 0x50A28BE6; aa = (t << 14) | (t >> (32 - 14));
	t = dd + ((aa & cc) | (bb & ~cc)) + X[10] + 0x50A28BE6; dd = (t << 14) | (t >> (32 - 14));
	t = cc + ((dd & bb) | (aa & ~bb)) + X[3] + 0x50A28BE6; cc = (t << 12) | (t >> (32 - 12));
	t = bb + ((cc & aa) | (dd & ~aa)) + X[12] + 0x50A28BE6; bb = (t << 6) | (t >> (32 - 6));

	t = aa + ((bb | ~cc) ^ dd) + X[6] + 0x5C4DD124; aa = (t << 9) | (t >> (32 - 9));
	t = dd + ((aa | ~bb) ^ cc) + X[11] + 0x5C4DD124; dd = (t << 13) | (t >> (32 - 13));
	t = cc + ((dd | ~aa) ^ bb) + X[3] + 0x5C4DD124; cc = (t << 15) | (t >> (32 - 15));
	t = bb + ((cc | ~dd) ^ aa) + X[7] + 0x5C4DD124; bb = (t << 7) | (t >> (32 - 7));
	t = aa + ((bb | ~cc) ^ dd) + X[0] + 0x5C4DD124; aa = (t << 12) | (t >> (32 - 12));
	t = dd + ((aa | ~bb) ^ cc) + X[13] + 0x5C4DD124; dd = (t << 8) | (t >> (32 - 8));
	t = cc + ((dd | ~aa) ^ bb) + X[5] + 0x5C4DD124; cc = (t << 9) | (t >> (32 - 9));
	t = bb + ((cc | ~dd) ^ aa) + X[10] + 0x5C4DD124; bb = (t << 11) | (t >> (32 - 11));
	t = aa + ((bb | ~cc) ^ dd) + X[14] + 0x5C4DD124; aa = (t << 7) | (t >> (32 - 7));
	t = dd + ((aa | ~bb) ^ cc) + X[15] + 0x5C4DD124; dd = (t << 7) | (t >> (32 - 7));
	t = cc + ((dd | ~aa) ^ bb) + X[8] + 0x5C4DD124; cc = (t << 12) | (t >> (32 - 12));
	t = bb + ((cc | ~dd) ^ aa) + X[12] + 0x5C4DD124; bb = (t << 7) | (t >> (32 - 7));
	t = aa + ((bb | ~cc) ^ dd) + X[4] + 0x5C4DD124; aa = (t << 6) | (t >> (32 - 6));
	t = dd + ((aa | ~bb) ^ cc) + X[9] + 0x5C4DD124; dd = (t << 15) | (t >> (32 - 15));
	t = cc + ((dd | ~aa) ^ bb) + X[1] + 0x5C4DD124; cc = (t << 13) | (t >> (32 - 13));
	t = bb + ((cc | ~dd) ^ aa) + X[2] + 0x5C4DD124; bb = (t << 11) | (t >> (32 - 11));

	t = aa + ((bb & cc) | (~bb & dd)) + X[15] + 0x6D703EF3; aa = (t << 9) | (t >> (32 - 9));
	t = dd + ((aa & bb) | (~aa & cc)) + X[5] + 0x6D703EF3; dd = (t << 7) | (t >> (32 - 7));
	t = cc + ((dd & aa) | (~dd & bb)) + X[1] + 0x6D703EF3; cc = (t << 15) | (t >> (32 - 15));
	t = bb + ((cc & dd) | (~cc & aa)) + X[3] + 0x6D703EF3; bb = (t << 11) | (t >> (32 - 11));
	t = aa + ((bb & cc) | (~bb & dd)) + X[7] + 0x6D703EF3; aa = (t << 8) | (t >> (32 - 8));
	t = dd + ((aa & bb) | (~aa & cc)) + X[14] + 0x6D703EF3; dd = (t << 6) | (t >> (32 - 6));
	t = cc + ((dd & aa) | (~dd & bb)) + X[6] + 0x6D703EF3; cc = (t << 6) | (t >> (32 - 6));
	t = bb + ((cc & dd) | (~cc & aa)) + X[9] + 0x6D703EF3; bb = (t << 14) | (t >> (32 - 14));
	t = aa + ((bb & cc) | (~bb & dd)) + X[11] + 0x6D703EF3; aa = (t << 12) | (t >> (32 - 12));
	t = dd + ((aa & bb) | (~aa & cc)) + X[8] + 0x6D703EF3; dd = (t << 13) | (t >> (32 - 13));
	t = cc + ((dd & aa) | (~dd & bb)) + X[12] + 0x6D703EF3; cc = (t << 5) | (t >> (32 - 5));
	t = bb + ((cc & dd) | (~cc & aa)) + X[2] + 0x6D703EF3; bb = (t << 14) | (t >> (32 - 14));
	t = aa + ((bb & cc) | (~bb & dd)) + X[10] + 0x6D703EF3; aa = (t << 13) | (t >> (32 - 13));
	t = dd + ((aa & bb) | (~aa & cc)) + X[0] + 0x6D703EF3; dd = (t << 13) | (t >> (32 - 13));
	t = cc + ((dd & aa) | (~dd & bb)) + X[4] + 0x6D703EF3; cc = (t << 7) | (t >> (32 - 7));
	t = bb + ((cc & dd) | (~cc & aa)) + X[13] + 0x6D703EF3; bb = (t << 5) | (t >> (32 - 5));

	t = aa + (bb ^ cc ^ dd) + X[8]; aa = (t << 15) | (t >> (32 - 15));
	t = dd + (aa ^ bb ^ cc) + X[6]; dd = (t << 5) | (t >> (32 - 5));
	t = cc + (dd ^ aa ^ bb) + X[4]; cc = (t << 8) | (t >> (32 - 8));
	t = bb + (cc ^ dd ^ aa) + X[1]; bb = (t << 11) | (t >> (32 - 11));
	t = aa + (bb ^ cc ^ dd) + X[3]; aa = (t << 14) | (t >> (32 - 14));
	t = dd + (aa ^ bb ^ cc) + X[11]; dd = (t << 14) | (t >> (32 - 14));
	t = cc + (dd ^ aa ^ bb) + X[15]; cc = (t << 6) | (t >> (32 - 6));
	t = bb + (cc ^ dd ^ aa) + X[0]; bb = (t << 14) | (t >> (32 - 14));
	t = aa + (bb ^ cc ^ dd) + X[5]; aa = (t << 6) | (t >> (32 - 6));
	t = dd + (aa ^ bb ^ cc) + X[12]; dd = (t << 9) | (t >> (32 - 9));
	t = cc + (dd ^ aa ^ bb) + X[2]; cc = (t << 12) | (t >> (32 - 12));
	t = bb + (cc ^ dd ^ aa) + X[13]; bb = (t << 9) | (t >> (32 - 9));
	t = aa + (bb ^ cc ^ dd) + X[9]; aa = (t << 12) | (t >> (32 - 12));
	t = dd + (aa ^ bb ^ cc) + X[7]; dd = (t << 5) | (t >> (32 - 5));
	t = cc + (dd ^ aa ^ bb) + X[10]; cc = (t << 15) | (t >> (32 - 15));
	t = bb + (cc ^ dd ^ aa) + X[14]; bb = (t << 8) | (t >> (32 - 8));

	dd += c + CurrentHash[1];
	CurrentHash[1] = CurrentHash[2] + d + aa;
	CurrentHash[2] = CurrentHash[3] + a + bb;
	CurrentHash[3] = CurrentHash[0] + b + cc;
	CurrentHash[0] = dd;

	memset(X, 0, sizeof(X));
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
}

