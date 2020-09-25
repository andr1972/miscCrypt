#include "DCPh_md5.h"
#include "Util.h"
#include "Exception.h"

using namespace dcpcrypt;

DCPh_md5::DCPh_md5()
{
}


DCPh_md5::~DCPh_md5()
{
}

std::string DCPh_md5::getAlgorithm()
{
	return "md5";
}

int DCPh_md5::getHashSize()
{
	return 128;
}

bool DCPh_md5::selfTest()
{
	const uint8_t Test1Out[16] = { 0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72 };
	const uint8_t Test2Out[16] = { 0xc3,0xfc,0xd3,0xd7,0x61,0x92,0xe4,0x00,0x7d,0xfb,0x49,0x6c,0xca,0x67,0xe1,0x3b };
	uint8_t TestOut[16];
	init();
	updateStr("abc");
	final(TestOut);
	bool result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
	init();
	updateStr("abcdefghijklmnopqrstuvwxyz");
	final(TestOut);
	result = memcmp(TestOut, Test2Out, sizeof(Test2Out)) == 0 && result;
	return result;
}

void DCPh_md5::init()
{
	burn();
	CurrentHash[0] = 0x67452301;
	CurrentHash[1] = 0xefcdab89;
	CurrentHash[2] = 0x98badcfe;
	CurrentHash[3] = 0x10325476;
	fInitialized = true;
}

void DCPh_md5::burn()
{
	lenHi = 0; lenLo = 0;
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
	memset(CurrentHash, 0, sizeof(CurrentHash));
	fInitialized = false;
}

void DCPh_md5::update(const unsigned char *buffer, uint32_t size)
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


void DCPh_md5::final(uint8_t * digest)
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


void DCPh_md5::compress()
{
	uint32_t Data[16];
	uint32_t A, B, C, D;

	memset(Data, 0, sizeof(Data));
	memmove(Data, HashBuffer, sizeof(Data));

	A = CurrentHash[0];
	B = CurrentHash[1];
	C = CurrentHash[2];
	D = CurrentHash[3];

	A = B + LRot32(A + (D ^ (B & (C ^ D))) + Data[0] + 0xd76aa478, 7);
	D = A + LRot32(D + (C ^ (A & (B ^ C))) + Data[1] + 0xe8c7b756, 12);
	C = D + LRot32(C + (B ^ (D & (A ^ B))) + Data[2] + 0x242070db, 17);
	B = C + LRot32(B + (A ^ (C & (D ^ A))) + Data[3] + 0xc1bdceee, 22);
	A = B + LRot32(A + (D ^ (B & (C ^ D))) + Data[4] + 0xf57c0faf, 7);
	D = A + LRot32(D + (C ^ (A & (B ^ C))) + Data[5] + 0x4787c62a, 12);
	C = D + LRot32(C + (B ^ (D & (A ^ B))) + Data[6] + 0xa8304613, 17);
	B = C + LRot32(B + (A ^ (C & (D ^ A))) + Data[7] + 0xfd469501, 22);
	A = B + LRot32(A + (D ^ (B & (C ^ D))) + Data[8] + 0x698098d8, 7);
	D = A + LRot32(D + (C ^ (A & (B ^ C))) + Data[9] + 0x8b44f7af, 12);
	C = D + LRot32(C + (B ^ (D & (A ^ B))) + Data[10] + 0xffff5bb1, 17);
	B = C + LRot32(B + (A ^ (C & (D ^ A))) + Data[11] + 0x895cd7be, 22);
	A = B + LRot32(A + (D ^ (B & (C ^ D))) + Data[12] + 0x6b901122, 7);
	D = A + LRot32(D + (C ^ (A & (B ^ C))) + Data[13] + 0xfd987193, 12);
	C = D + LRot32(C + (B ^ (D & (A ^ B))) + Data[14] + 0xa679438e, 17);
	B = C + LRot32(B + (A ^ (C & (D ^ A))) + Data[15] + 0x49b40821, 22);

	A = B + LRot32(A + (C ^ (D & (B ^ C))) + Data[1] + 0xf61e2562, 5);
	D = A + LRot32(D + (B ^ (C & (A ^ B))) + Data[6] + 0xc040b340, 9);
	C = D + LRot32(C + (A ^ (B & (D ^ A))) + Data[11] + 0x265e5a51, 14);
	B = C + LRot32(B + (D ^ (A & (C ^ D))) + Data[0] + 0xe9b6c7aa, 20);
	A = B + LRot32(A + (C ^ (D & (B ^ C))) + Data[5] + 0xd62f105d, 5);
	D = A + LRot32(D + (B ^ (C & (A ^ B))) + Data[10] + 0x02441453, 9);
	C = D + LRot32(C + (A ^ (B & (D ^ A))) + Data[15] + 0xd8a1e681, 14);
	B = C + LRot32(B + (D ^ (A & (C ^ D))) + Data[4] + 0xe7d3fbc8, 20);
	A = B + LRot32(A + (C ^ (D & (B ^ C))) + Data[9] + 0x21e1cde6, 5);
	D = A + LRot32(D + (B ^ (C & (A ^ B))) + Data[14] + 0xc33707d6, 9);
	C = D + LRot32(C + (A ^ (B & (D ^ A))) + Data[3] + 0xf4d50d87, 14);
	B = C + LRot32(B + (D ^ (A & (C ^ D))) + Data[8] + 0x455a14ed, 20);
	A = B + LRot32(A + (C ^ (D & (B ^ C))) + Data[13] + 0xa9e3e905, 5);
	D = A + LRot32(D + (B ^ (C & (A ^ B))) + Data[2] + 0xfcefa3f8, 9);
	C = D + LRot32(C + (A ^ (B & (D ^ A))) + Data[7] + 0x676f02d9, 14);
	B = C + LRot32(B + (D ^ (A & (C ^ D))) + Data[12] + 0x8d2a4c8a, 20);

	A = B + LRot32(A + (B ^ C ^ D) + Data[5] + 0xfffa3942, 4);
	D = A + LRot32(D + (A ^ B ^ C) + Data[8] + 0x8771f681, 11);
	C = D + LRot32(C + (D ^ A ^ B) + Data[11] + 0x6d9d6122, 16);
	B = C + LRot32(B + (C ^ D ^ A) + Data[14] + 0xfde5380c, 23);
	A = B + LRot32(A + (B ^ C ^ D) + Data[1] + 0xa4beea44, 4);
	D = A + LRot32(D + (A ^ B ^ C) + Data[4] + 0x4bdecfa9, 11);
	C = D + LRot32(C + (D ^ A ^ B) + Data[7] + 0xf6bb4b60, 16);
	B = C + LRot32(B + (C ^ D ^ A) + Data[10] + 0xbebfbc70, 23);
	A = B + LRot32(A + (B ^ C ^ D) + Data[13] + 0x289b7ec6, 4);
	D = A + LRot32(D + (A ^ B ^ C) + Data[0] + 0xeaa127fa, 11);
	C = D + LRot32(C + (D ^ A ^ B) + Data[3] + 0xd4ef3085, 16);
	B = C + LRot32(B + (C ^ D ^ A) + Data[6] + 0x04881d05, 23);
	A = B + LRot32(A + (B ^ C ^ D) + Data[9] + 0xd9d4d039, 4);
	D = A + LRot32(D + (A ^ B ^ C) + Data[12] + 0xe6db99e5, 11);
	C = D + LRot32(C + (D ^ A ^ B) + Data[15] + 0x1fa27cf8, 16);
	B = C + LRot32(B + (C ^ D ^ A) + Data[2] + 0xc4ac5665, 23);

	A = B + LRot32(A + (C ^ (B | (~D))) + Data[0] + 0xf4292244, 6);
	D = A + LRot32(D + (B ^ (A | (~C))) + Data[7] + 0x432aff97, 10);
	C = D + LRot32(C + (A ^ (D | (~B))) + Data[14] + 0xab9423a7, 15);
	B = C + LRot32(B + (D ^ (C | (~A))) + Data[5] + 0xfc93a039, 21);
	A = B + LRot32(A + (C ^ (B | (~D))) + Data[12] + 0x655b59c3, 6);
	D = A + LRot32(D + (B ^ (A | (~C))) + Data[3] + 0x8f0ccc92, 10);
	C = D + LRot32(C + (A ^ (D | (~B))) + Data[10] + 0xffeff47d, 15);
	B = C + LRot32(B + (D ^ (C | (~A))) + Data[1] + 0x85845dd1, 21);
	A = B + LRot32(A + (C ^ (B | (~D))) + Data[8] + 0x6fa87e4f, 6);
	D = A + LRot32(D + (B ^ (A | (~C))) + Data[15] + 0xfe2ce6e0, 10);
	C = D + LRot32(C + (A ^ (D | (~B))) + Data[6] + 0xa3014314, 15);
	B = C + LRot32(B + (D ^ (C | (~A))) + Data[13] + 0x4e0811a1, 21);
	A = B + LRot32(A + (C ^ (B | (~D))) + Data[4] + 0xf7537e82, 6);
	D = A + LRot32(D + (B ^ (A | (~C))) + Data[11] + 0xbd3af235, 10);
	C = D + LRot32(C + (A ^ (D | (~B))) + Data[2] + 0x2ad7d2bb, 15);
	B = C + LRot32(B + (D ^ (C | (~A))) + Data[9] + 0xeb86d391, 21);

	CurrentHash[0] += A;
	CurrentHash[1] += B;
	CurrentHash[2] += C;
	CurrentHash[3] += D;
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
}

