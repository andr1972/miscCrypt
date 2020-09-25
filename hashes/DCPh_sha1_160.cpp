#include "DCPh_sha1_160.h"
#include "Util.h"
#include "Exception.h"

using namespace dcpcrypt;

DCPh_sha1_160::DCPh_sha1_160()
{
}


DCPh_sha1_160::~DCPh_sha1_160()
{
}

std::string DCPh_sha1_160::getAlgorithm()
{
	return "sha1-160";
}

int DCPh_sha1_160::getHashSize()
{
	return 160;
}

bool DCPh_sha1_160::selfTest()
{
	const uint8_t Test1Out[20] = { 0xA9,0x99,0x3E,0x36,0x47,0x06,0x81,0x6A,0xBA,0x3E,0x25,0x71,0x78,0x50,0xC2,0x6C,0x9C,0xD0,0xD8,0x9D };
	const uint8_t Test2Out[20] = { 0x84,0x98,0x3E,0x44,0x1C,0x3B,0xD2,0x6E,0xBA,0xAE,0x4A,0xA1,0xF9,0x51,0x29,0xE5,0xE5,0x46,0x70,0xF1 };
	const uint8_t Test3Out[20] = { 0x4c,0x1c,0xcc,0x3a,0x63,0x63,0xa7,0x3d,0x8e,0xad,0xc0,0xc8,0xa0,0x83,0xd9,0xc2,0x74,0x26,0x68,0x06 };
	uint8_t TestOut[20];
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

void DCPh_sha1_160::init()
{
	burn();
	CurrentHash[0] = 0x67452301;
	CurrentHash[1] = 0xefcdab89;
	CurrentHash[2] = 0x98badcfe;
	CurrentHash[3] = 0x10325476;
	CurrentHash[4] = 0xc3d2e1f0;
	fInitialized = true;
}

void DCPh_sha1_160::burn()
{
	lenHi = 0; lenLo = 0;
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
	memset(CurrentHash, 0, sizeof(CurrentHash));
	fInitialized = false;
}

void DCPh_sha1_160::update(const unsigned char *buffer, uint32_t size)
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


void DCPh_sha1_160::final(uint8_t * digest)
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
	memmove(digest, CurrentHash, sizeof(CurrentHash));
	burn();
}


void DCPh_sha1_160::compress()
{
	uint32_t A, B, C, D, E;
	uint32_t W[80];
	memset(W, 0, sizeof(W));
	memmove(W, HashBuffer, sizeof(W));

	for (uint32_t i = 0; i<16; i++)
		W[i] = SwapDWord(W[i]);
	for (uint32_t i = 16; i<80; i++)
		W[i]  = ((W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]) << 1) | ((W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]) >> 31);
	A = CurrentHash[0]; B = CurrentHash[1]; C = CurrentHash[2]; D = CurrentHash[3]; E = CurrentHash[4];

	E += ((A << 5) | (A >> 27)) + (D ^ (B & (C ^ D))) + 0x5A827999 + W[0]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + (C ^ (A & (B ^ C))) + 0x5A827999 + W[1]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + (B ^ (E & (A ^ B))) + 0x5A827999 + W[2]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + (A ^ (D & (E ^ A))) + 0x5A827999 + W[3]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + (E ^ (C & (D ^ E))) + 0x5A827999 + W[4]; C = (C << 30) | (C >> 2);
	E += ((A << 5) | (A >> 27)) + (D ^ (B & (C ^ D))) + 0x5A827999 + W[5]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + (C ^ (A & (B ^ C))) + 0x5A827999 + W[6]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + (B ^ (E & (A ^ B))) + 0x5A827999 + W[7]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + (A ^ (D & (E ^ A))) + 0x5A827999 + W[8]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + (E ^ (C & (D ^ E))) + 0x5A827999 + W[9]; C = (C << 30) | (C >> 2);
	E += ((A << 5) | (A >> 27)) + (D ^ (B & (C ^ D))) + 0x5A827999 + W[10]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + (C ^ (A & (B ^ C))) + 0x5A827999 + W[11]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + (B ^ (E & (A ^ B))) + 0x5A827999 + W[12]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + (A ^ (D & (E ^ A))) + 0x5A827999 + W[13]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + (E ^ (C & (D ^ E))) + 0x5A827999 + W[14]; C = (C << 30) | (C >> 2);
	E += ((A << 5) | (A >> 27)) + (D ^ (B & (C ^ D))) + 0x5A827999 + W[15]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + (C ^ (A & (B ^ C))) + 0x5A827999 + W[16]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + (B ^ (E & (A ^ B))) + 0x5A827999 + W[17]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + (A ^ (D & (E ^ A))) + 0x5A827999 + W[18]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + (E ^ (C & (D ^ E))) + 0x5A827999 + W[19]; C = (C << 30) | (C >> 2);

	E += ((A << 5) | (A >> 27)) + (B ^ C ^ D) + 0x6ED9EBA1 + W[20]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + (A ^ B ^ C) + 0x6ED9EBA1 + W[21]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + (E ^ A ^ B) + 0x6ED9EBA1 + W[22]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + (D ^ E ^ A) + 0x6ED9EBA1 + W[23]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + (C ^ D ^ E) + 0x6ED9EBA1 + W[24]; C = (C << 30) | (C >> 2);
	E += ((A << 5) | (A >> 27)) + (B ^ C ^ D) + 0x6ED9EBA1 + W[25]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + (A ^ B ^ C) + 0x6ED9EBA1 + W[26]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + (E ^ A ^ B) + 0x6ED9EBA1 + W[27]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + (D ^ E ^ A) + 0x6ED9EBA1 + W[28]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + (C ^ D ^ E) + 0x6ED9EBA1 + W[29]; C = (C << 30) | (C >> 2);
	E += ((A << 5) | (A >> 27)) + (B ^ C ^ D) + 0x6ED9EBA1 + W[30]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + (A ^ B ^ C) + 0x6ED9EBA1 + W[31]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + (E ^ A ^ B) + 0x6ED9EBA1 + W[32]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + (D ^ E ^ A) + 0x6ED9EBA1 + W[33]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + (C ^ D ^ E) + 0x6ED9EBA1 + W[34]; C = (C << 30) | (C >> 2);
	E += ((A << 5) | (A >> 27)) + (B ^ C ^ D) + 0x6ED9EBA1 + W[35]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + (A ^ B ^ C) + 0x6ED9EBA1 + W[36]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + (E ^ A ^ B) + 0x6ED9EBA1 + W[37]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + (D ^ E ^ A) + 0x6ED9EBA1 + W[38]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + (C ^ D ^ E) + 0x6ED9EBA1 + W[39]; C = (C << 30) | (C >> 2);

	E += ((A << 5) | (A >> 27)) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + W[40]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + W[41]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + W[42]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + W[43]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + W[44]; C = (C << 30) | (C >> 2);
	E += ((A << 5) | (A >> 27)) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + W[45]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + W[46]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + W[47]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + W[48]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + W[49]; C = (C << 30) | (C >> 2);
	E += ((A << 5) | (A >> 27)) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + W[50]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + W[51]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + W[52]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + W[53]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + W[54]; C = (C << 30) | (C >> 2);
	E += ((A << 5) | (A >> 27)) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + W[55]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + W[56]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + W[57]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + W[58]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + W[59]; C = (C << 30) | (C >> 2);

	E += ((A << 5) | (A >> 27)) + (B ^ C ^ D) + 0xCA62C1D6 + W[60]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + (A ^ B ^ C) + 0xCA62C1D6 + W[61]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + (E ^ A ^ B) + 0xCA62C1D6 + W[62]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + (D ^ E ^ A) + 0xCA62C1D6 + W[63]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + (C ^ D ^ E) + 0xCA62C1D6 + W[64]; C = (C << 30) | (C >> 2);
	E += ((A << 5) | (A >> 27)) + (B ^ C ^ D) + 0xCA62C1D6 + W[65]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + (A ^ B ^ C) + 0xCA62C1D6 + W[66]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + (E ^ A ^ B) + 0xCA62C1D6 + W[67]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + (D ^ E ^ A) + 0xCA62C1D6 + W[68]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + (C ^ D ^ E) + 0xCA62C1D6 + W[69]; C = (C << 30) | (C >> 2);
	E += ((A << 5) | (A >> 27)) + (B ^ C ^ D) + 0xCA62C1D6 + W[70]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + (A ^ B ^ C) + 0xCA62C1D6 + W[71]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + (E ^ A ^ B) + 0xCA62C1D6 + W[72]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + (D ^ E ^ A) + 0xCA62C1D6 + W[73]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + (C ^ D ^ E) + 0xCA62C1D6 + W[74]; C = (C << 30) | (C >> 2);
	E += ((A << 5) | (A >> 27)) + (B ^ C ^ D) + 0xCA62C1D6 + W[75]; B = (B << 30) | (B >> 2);
	D += ((E << 5) | (E >> 27)) + (A ^ B ^ C) + 0xCA62C1D6 + W[76]; A = (A << 30) | (A >> 2);
	C += ((D << 5) | (D >> 27)) + (E ^ A ^ B) + 0xCA62C1D6 + W[77]; E = (E << 30) | (E >> 2);
	B += ((C << 5) | (C >> 27)) + (D ^ E ^ A) + 0xCA62C1D6 + W[78]; D = (D << 30) | (D >> 2);
	A += ((B << 5) | (B >> 27)) + (C ^ D ^ E) + 0xCA62C1D6 + W[79]; C = (C << 30) | (C >> 2);

	CurrentHash[0] = CurrentHash[0] + A;
	CurrentHash[1] = CurrentHash[1] + B;
	CurrentHash[2] = CurrentHash[2] + C;
	CurrentHash[3] = CurrentHash[3] + D;
	CurrentHash[4] = CurrentHash[4] + E;

	memset(W, 0, sizeof(W));
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
}

