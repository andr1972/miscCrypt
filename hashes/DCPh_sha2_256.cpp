#include "DCPh_sha2_256.h"
#include "Util.h"
#include "Exception.h"

using namespace dcpcrypt;

DCPh_sha2_256::DCPh_sha2_256()
{
}


DCPh_sha2_256::~DCPh_sha2_256()
{
}

std::string DCPh_sha2_256::getAlgorithm()
{
	return "sha2-256";
}

int DCPh_sha2_256::getHashSize()
{
	return 256;
}

bool DCPh_sha2_256::selfTest()
{
	const uint8_t Test1Out[32] = { 0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
		0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
	const uint8_t Test2Out[32] = { 0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
		0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1 };
	const uint8_t Test3Out[32] = { 0x95,0xf1,0x0b,0x70,0x5d,0x68,0x0f,0xa4,0xfe,0x98,0x9f,0x83,0x25,0x9c,0xff,0x55,
		0x46,0xf0,0xec,0x8e,0xa1,0xb3,0xf2,0xcb,0x0a,0x91,0x98,0x73,0x4e,0xfb,0xd4,0xe7 };
	uint8_t TestOut[32];
	init();
	updateStr("abc");
	final(TestOut);
	bool result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
	init();
	updateStr("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
	final(TestOut);
	result = memcmp(TestOut, Test2Out, sizeof(Test2Out)) == 0 && result;
	init();
	//more than one 64 byte block
	updateStr("300ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789xyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789xyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789xyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789xy*300ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk");
	final(TestOut);
	result = memcmp(TestOut, Test3Out, sizeof(Test3Out)) == 0 && result;
	//the same divided to many updates
	init();
	updateStr("300");
	updateStr("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	updateStr("abcdefghijklmnopqrstuvwxyz");
	updateStr("0123456789xy");
	updateStr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcd");
	updateStr("efghijklmnopqrstuvwxyz012345");
	updateStr("6789xyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789xyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk");
	updateStr("lmnopqrstuvwxyz0123456789xy*300ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	updateStr("abcdefghijk");
	final(TestOut);
	result = memcmp(TestOut, Test3Out, sizeof(Test3Out)) == 0 && result;
	return result;
}

void DCPh_sha2_256::init()
{
	burn();
	CurrentHash[0] = 0x6a09e667;
	CurrentHash[1] = 0xbb67ae85;
	CurrentHash[2] = 0x3c6ef372;
	CurrentHash[3] = 0xa54ff53a;
	CurrentHash[4] = 0x510e527f;
	CurrentHash[5] = 0x9b05688c;
	CurrentHash[6] = 0x1f83d9ab;
	CurrentHash[7] = 0x5be0cd19;
	fInitialized = true;
}

void DCPh_sha2_256::burn()
{
	lenHi = 0; lenLo = 0;
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
	memset(CurrentHash, 0, sizeof(CurrentHash));
	fInitialized = false;
}

void DCPh_sha2_256::update(const unsigned char *buffer, uint32_t size)
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


void DCPh_sha2_256::final(uint8_t * digest)
{
	if (!fInitialized)
		throw EDCP_hash("Hash not initialized");
	HashBuffer[index] = 0x80;
	if (index >= 56)
		compress();
	*((uint32_t*)(HashBuffer + 56)) = SwapDWord(lenHi);
	*((uint32_t*)(HashBuffer + 60)) = SwapDWord(lenLo);
	compress();
	CurrentHash[0] = SwapDWord(CurrentHash[0]);
	CurrentHash[1] = SwapDWord(CurrentHash[1]);
	CurrentHash[2] = SwapDWord(CurrentHash[2]);
	CurrentHash[3] = SwapDWord(CurrentHash[3]);
	CurrentHash[4] = SwapDWord(CurrentHash[4]);
	CurrentHash[5] = SwapDWord(CurrentHash[5]);
	CurrentHash[6] = SwapDWord(CurrentHash[6]);
	CurrentHash[7] = SwapDWord(CurrentHash[7]);
	memmove(digest, CurrentHash, sizeof(CurrentHash));
	burn();
}


void DCPh_sha2_256::compress()
{
	uint32_t a, b, c, d, e, f, g, h, t1, t2;
	uint32_t W[64];
	memset(W, 0, sizeof(W));
	a = CurrentHash[0]; b = CurrentHash[1]; c = CurrentHash[2]; d = CurrentHash[3];
	e = CurrentHash[4]; f = CurrentHash[5]; g = CurrentHash[6]; h = CurrentHash[7];
	memmove(W, HashBuffer, sizeof(W));
	for (uint32_t i = 0; i<16; i++)
		W[i] = SwapDWord(W[i]);
	for (uint32_t i = 16; i<64; i++)
		W[i] = (((W[i - 2] >> 17) | (W[i - 2] << 15)) ^ ((W[i - 2] >> 19) | (W[i - 2] << 13)) ^
		(W[i - 2] >> 10)) + W[i - 7] + (((W[i - 15] >> 7) | (W[i - 15] << 25)) ^
			((W[i - 15] >> 18) | (W[i - 15] << 14)) ^ (W[i - 15] >> 3)) + W[i - 16];

	/*Non - optimised version
	for (uint32_t i = 0; i < 64; i++)
	{
		t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) +
			((e & f) ^ (~e & g)) + K[i] + W[i];
		t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) ^ (a << 10))) +
			((a & b) ^ (a & c) ^ (b & c));
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}*/

	t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + 0x428a2f98 + W[0]; t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) ^ (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)); h = t1 + t2; d = d + t1;
	t1 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + 0x71374491 + W[1]; t2 = (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) ^ (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)); g = t1 + t2; c = c + t1;
	t1 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + 0xb5c0fbcf + W[2]; t2 = (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) ^ (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)); f = t1 + t2; b = b + t1;
	t1 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + 0xe9b5dba5 + W[3]; t2 = (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) ^ (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)); e = t1 + t2; a = a + t1;
	t1 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + 0x3956c25b + W[4]; t2 = (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) ^ (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)); d = t1 + t2; h = h + t1;
	t1 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + 0x59f111f1 + W[5]; t2 = (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) ^ (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)); c = t1 + t2; g = g + t1;
	t1 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + 0x923f82a4 + W[6]; t2 = (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) ^ (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)); b = t1 + t2; f = f + t1;
	t1 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + 0xab1c5ed5 + W[7]; t2 = (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) ^ (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)); a = t1 + t2; e = e + t1;
	t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + 0xd807aa98 + W[8]; t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) ^ (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)); h = t1 + t2; d = d + t1;
	t1 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + 0x12835b01 + W[9]; t2 = (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) ^ (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)); g = t1 + t2; c = c + t1;
	t1 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + 0x243185be + W[10]; t2 = (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) ^ (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)); f = t1 + t2; b = b + t1;
	t1 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + 0x550c7dc3 + W[11]; t2 = (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) ^ (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)); e = t1 + t2; a = a + t1;
	t1 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + 0x72be5d74 + W[12]; t2 = (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) ^ (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)); d = t1 + t2; h = h + t1;
	t1 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + 0x80deb1fe + W[13]; t2 = (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) ^ (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)); c = t1 + t2; g = g + t1;
	t1 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + 0x9bdc06a7 + W[14]; t2 = (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) ^ (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)); b = t1 + t2; f = f + t1;
	t1 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + 0xc19bf174 + W[15]; t2 = (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) ^ (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)); a = t1 + t2; e = e + t1;
	t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + 0xe49b69c1 + W[16]; t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) ^ (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)); h = t1 + t2; d = d + t1;
	t1 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + 0xefbe4786 + W[17]; t2 = (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) ^ (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)); g = t1 + t2; c = c + t1;
	t1 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + 0x0fc19dc6 + W[18]; t2 = (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) ^ (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)); f = t1 + t2; b = b + t1;
	t1 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + 0x240ca1cc + W[19]; t2 = (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) ^ (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)); e = t1 + t2; a = a + t1;
	t1 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + 0x2de92c6f + W[20]; t2 = (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) ^ (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)); d = t1 + t2; h = h + t1;
	t1 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + 0x4a7484aa + W[21]; t2 = (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) ^ (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)); c = t1 + t2; g = g + t1;
	t1 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + 0x5cb0a9dc + W[22]; t2 = (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) ^ (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)); b = t1 + t2; f = f + t1;
	t1 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + 0x76f988da + W[23]; t2 = (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) ^ (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)); a = t1 + t2; e = e + t1;
	t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + 0x983e5152 + W[24]; t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) ^ (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)); h = t1 + t2; d = d + t1;
	t1 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + 0xa831c66d + W[25]; t2 = (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) ^ (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)); g = t1 + t2; c = c + t1;
	t1 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + 0xb00327c8 + W[26]; t2 = (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) ^ (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)); f = t1 + t2; b = b + t1;
	t1 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + 0xbf597fc7 + W[27]; t2 = (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) ^ (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)); e = t1 + t2; a = a + t1;
	t1 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + 0xc6e00bf3 + W[28]; t2 = (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) ^ (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)); d = t1 + t2; h = h + t1;
	t1 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + 0xd5a79147 + W[29]; t2 = (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) ^ (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)); c = t1 + t2; g = g + t1;
	t1 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + 0x06ca6351 + W[30]; t2 = (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) ^ (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)); b = t1 + t2; f = f + t1;
	t1 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + 0x14292967 + W[31]; t2 = (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) ^ (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)); a = t1 + t2; e = e + t1;
	t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + 0x27b70a85 + W[32]; t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) ^ (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)); h = t1 + t2; d = d + t1;
	t1 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + 0x2e1b2138 + W[33]; t2 = (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) ^ (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)); g = t1 + t2; c = c + t1;
	t1 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + 0x4d2c6dfc + W[34]; t2 = (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) ^ (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)); f = t1 + t2; b = b + t1;
	t1 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + 0x53380d13 + W[35]; t2 = (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) ^ (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)); e = t1 + t2; a = a + t1;
	t1 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + 0x650a7354 + W[36]; t2 = (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) ^ (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)); d = t1 + t2; h = h + t1;
	t1 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + 0x766a0abb + W[37]; t2 = (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) ^ (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)); c = t1 + t2; g = g + t1;
	t1 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + 0x81c2c92e + W[38]; t2 = (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) ^ (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)); b = t1 + t2; f = f + t1;
	t1 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + 0x92722c85 + W[39]; t2 = (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) ^ (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)); a = t1 + t2; e = e + t1;
	t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + 0xa2bfe8a1 + W[40]; t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) ^ (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)); h = t1 + t2; d = d + t1;
	t1 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + 0xa81a664b + W[41]; t2 = (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) ^ (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)); g = t1 + t2; c = c + t1;
	t1 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + 0xc24b8b70 + W[42]; t2 = (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) ^ (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)); f = t1 + t2; b = b + t1;
	t1 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + 0xc76c51a3 + W[43]; t2 = (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) ^ (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)); e = t1 + t2; a = a + t1;
	t1 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + 0xd192e819 + W[44]; t2 = (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) ^ (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)); d = t1 + t2; h = h + t1;
	t1 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + 0xd6990624 + W[45]; t2 = (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) ^ (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)); c = t1 + t2; g = g + t1;
	t1 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + 0xf40e3585 + W[46]; t2 = (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) ^ (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)); b = t1 + t2; f = f + t1;
	t1 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + 0x106aa070 + W[47]; t2 = (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) ^ (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)); a = t1 + t2; e = e + t1;
	t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + 0x19a4c116 + W[48]; t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) ^ (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)); h = t1 + t2; d = d + t1;
	t1 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + 0x1e376c08 + W[49]; t2 = (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) ^ (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)); g = t1 + t2; c = c + t1;
	t1 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + 0x2748774c + W[50]; t2 = (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) ^ (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)); f = t1 + t2; b = b + t1;
	t1 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + 0x34b0bcb5 + W[51]; t2 = (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) ^ (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)); e = t1 + t2; a = a + t1;
	t1 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + 0x391c0cb3 + W[52]; t2 = (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) ^ (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)); d = t1 + t2; h = h + t1;
	t1 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + 0x4ed8aa4a + W[53]; t2 = (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) ^ (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)); c = t1 + t2; g = g + t1;
	t1 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + 0x5b9cca4f + W[54]; t2 = (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) ^ (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)); b = t1 + t2; f = f + t1;
	t1 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + 0x682e6ff3 + W[55]; t2 = (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) ^ (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)); a = t1 + t2; e = e + t1;
	t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + 0x748f82ee + W[56]; t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) ^ (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)); h = t1 + t2; d = d + t1;
	t1 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + 0x78a5636f + W[57]; t2 = (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) ^ (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)); g = t1 + t2; c = c + t1;
	t1 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + 0x84c87814 + W[58]; t2 = (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) ^ (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)); f = t1 + t2; b = b + t1;
	t1 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + 0x8cc70208 + W[59]; t2 = (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) ^ (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)); e = t1 + t2; a = a + t1;
	t1 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + 0x90befffa + W[60]; t2 = (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) ^ (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)); d = t1 + t2; h = h + t1;
	t1 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + 0xa4506ceb + W[61]; t2 = (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) ^ (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)); c = t1 + t2; g = g + t1;
	t1 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + 0xbef9a3f7 + W[62]; t2 = (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) ^ (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)); b = t1 + t2; f = f + t1;
	t1 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + 0xc67178f2 + W[63]; t2 = (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) ^ (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)); a = t1 + t2; e = e + t1;

	CurrentHash[0] = CurrentHash[0] + a;
	CurrentHash[1] = CurrentHash[1] + b;
	CurrentHash[2] = CurrentHash[2] + c;
	CurrentHash[3] = CurrentHash[3] + d;
	CurrentHash[4] = CurrentHash[4] + e;
	CurrentHash[5] = CurrentHash[5] + f;
	CurrentHash[6] = CurrentHash[6] + g;
	CurrentHash[7] = CurrentHash[7] + h;
	memset(W, 0, sizeof(W));
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
}

