#include "DCPh_md4.h"
#include "Util.h"
#include "Exception.h"

using namespace dcpcrypt;

DCPh_md4::DCPh_md4()
{
}


DCPh_md4::~DCPh_md4()
{
}

std::string DCPh_md4::getAlgorithm()
{
	return "md4";
}

int DCPh_md4::getHashSize()
{
	return 128;
}

bool DCPh_md4::selfTest()
{
	const uint8_t Test1Out[16] = { 0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d };
	const uint8_t Test2Out[16] = { 0xd7, 0x9e, 0x1c, 0x30, 0x8a, 0xa5, 0xbb, 0xcd, 0xee, 0xa8, 0xed, 0x63, 0xdf, 0x41, 0x2d, 0xa9 };
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

void DCPh_md4::init()
{
	burn();
	CurrentHash[0] = 0x67452301;
	CurrentHash[1] = 0xefcdab89;
	CurrentHash[2] = 0x98badcfe;
	CurrentHash[3] = 0x10325476;
	fInitialized = true;
}

void DCPh_md4::burn()
{
	lenHi = 0; lenLo = 0;
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
	memset(CurrentHash, 0, sizeof(CurrentHash));
	fInitialized = false;
}

void DCPh_md4::update(const unsigned char *buffer, uint32_t size)
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
			memmove(HashBuffer+index, PBuf, sizeof(HashBuffer) - index);
			size -= sizeof(HashBuffer) - index;
			PBuf += sizeof(HashBuffer) - index;
			compress();
		}
		else
		{
			memmove(HashBuffer+index, PBuf, size);
			index += size;
			size = 0;
		}
	}
}


void DCPh_md4::final(uint8_t * digest)
{
	if (!fInitialized)
		throw EDCP_hash("Hash not initialized");
	HashBuffer[index] = 0x80;
	if (index >= 56)
		compress();
	*((uint32_t*)(HashBuffer+56)) = lenLo;
	*((uint32_t*)(HashBuffer+60)) = lenHi;
	compress();
	memmove(digest, CurrentHash, sizeof(CurrentHash));
	burn();
}


void DCPh_md4::compress()
{
	uint32_t Data[16];
	uint32_t A, B, C, D;

	memset(Data, 0, sizeof(Data));
	memmove(Data, HashBuffer, sizeof(Data));

	A = CurrentHash[0];
	B = CurrentHash[1];
	C = CurrentHash[2];
	D = CurrentHash[3];

	A = LRot32(A + (D ^ (B & (C ^ D))) + Data[0], 3);
	D = LRot32(D + (C ^ (A & (B ^ C))) + Data[1], 7);
	C = LRot32(C + (B ^ (D & (A ^ B))) + Data[2], 11);
	B = LRot32(B + (A ^ (C & (D ^ A))) + Data[3], 19);
	A = LRot32(A + (D ^ (B & (C ^ D))) + Data[4], 3);
	D = LRot32(D + (C ^ (A & (B ^ C))) + Data[5], 7);
	C = LRot32(C + (B ^ (D & (A ^ B))) + Data[6], 11);
	B = LRot32(B + (A ^ (C & (D ^ A))) + Data[7], 19);
	A = LRot32(A + (D ^ (B & (C ^ D))) + Data[8], 3);
	D = LRot32(D + (C ^ (A & (B ^ C))) + Data[9], 7);
	C = LRot32(C + (B ^ (D & (A ^ B))) + Data[10], 11);
	B = LRot32(B + (A ^ (C & (D ^ A))) + Data[11], 19);
	A = LRot32(A + (D ^ (B & (C ^ D))) + Data[12], 3);
	D = LRot32(D + (C ^ (A & (B ^ C))) + Data[13], 7);
	C = LRot32(C + (B ^ (D & (A ^ B))) + Data[14], 11);
	B = LRot32(B + (A ^ (C & (D ^ A))) + Data[15], 19);

	A = LRot32(A + ((B & C) | (B & D) | (C & D)) + Data[0] + 0x5a827999, 3);
	D = LRot32(D + ((A & B) | (A & C) | (B & C)) + Data[4] + 0x5a827999, 5);
	C = LRot32(C + ((D & A) | (D & B) | (A & B)) + Data[8] + 0x5a827999, 9);
	B = LRot32(B + ((C & D) | (C & A) | (D & A)) + Data[12] + 0x5a827999, 13);
	A = LRot32(A + ((B & C) | (B & D) | (C & D)) + Data[1] + 0x5a827999, 3);
	D = LRot32(D + ((A & B) | (A & C) | (B & C)) + Data[5] + 0x5a827999, 5);
	C = LRot32(C + ((D & A) | (D & B) | (A & B)) + Data[9] + 0x5a827999, 9);
	B = LRot32(B + ((C & D) | (C & A) | (D & A)) + Data[13] + 0x5a827999, 13);
	A = LRot32(A + ((B & C) | (B & D) | (C & D)) + Data[2] + 0x5a827999, 3);
	D = LRot32(D + ((A & B) | (A & C) | (B & C)) + Data[6] + 0x5a827999, 5);
	C = LRot32(C + ((D & A) | (D & B) | (A & B)) + Data[10] + 0x5a827999, 9);
	B = LRot32(B + ((C & D) | (C & A) | (D & A)) + Data[14] + 0x5a827999, 13);
	A = LRot32(A + ((B & C) | (B & D) | (C & D)) + Data[3] + 0x5a827999, 3);
	D = LRot32(D + ((A & B) | (A & C) | (B & C)) + Data[7] + 0x5a827999, 5);
	C = LRot32(C + ((D & A) | (D & B) | (A & B)) + Data[11] + 0x5a827999, 9);
	B = LRot32(B + ((C & D) | (C & A) | (D & A)) + Data[15] + 0x5a827999, 13);

	A = LRot32(A + (B ^ C ^ D) + Data[0] + 0x6ed9eba1, 3);
	D = LRot32(D + (A ^ B ^ C) + Data[8] + 0x6ed9eba1, 9);
	C = LRot32(C + (D ^ A ^ B) + Data[4] + 0x6ed9eba1, 11);
	B = LRot32(B + (C ^ D ^ A) + Data[12] + 0x6ed9eba1, 15);
	A = LRot32(A + (B ^ C ^ D) + Data[2] + 0x6ed9eba1, 3);
	D = LRot32(D + (A ^ B ^ C) + Data[10] + 0x6ed9eba1, 9);
	C = LRot32(C + (D ^ A ^ B) + Data[6] + 0x6ed9eba1, 11);
	B = LRot32(B + (C ^ D ^ A) + Data[14] + 0x6ed9eba1, 15);
	A = LRot32(A + (B ^ C ^ D) + Data[1] + 0x6ed9eba1, 3);
	D = LRot32(D + (A ^ B ^ C) + Data[9] + 0x6ed9eba1, 9);
	C = LRot32(C + (D ^ A ^ B) + Data[5] + 0x6ed9eba1, 11);
	B = LRot32(B + (C ^ D ^ A) + Data[13] + 0x6ed9eba1, 15);
	A = LRot32(A + (B ^ C ^ D) + Data[3] + 0x6ed9eba1, 3);
	D = LRot32(D + (A ^ B ^ C) + Data[11] + 0x6ed9eba1, 9);
	C = LRot32(C + (D ^ A ^ B) + Data[7] + 0x6ed9eba1, 11);
	B = LRot32(B + (C ^ D ^ A) + Data[15] + 0x6ed9eba1, 15);

	CurrentHash[0] += A;
	CurrentHash[1] += B;
	CurrentHash[2] += C;
	CurrentHash[3] += D;
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
}

