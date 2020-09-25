#include "DCPc_serpent.h"
#include "Exception.h"
#include "Util.h"
#include <vector>

using namespace dcpcrypt;

DCPc_serpent::DCPc_serpent()
{
}

DCPc_serpent::~DCPc_serpent()
{
}

int DCPc_serpent::getMaxKeySize()
{
	return 256;
}

DCPenum DCPc_serpent::getId()
{
	return DCPenum::c_serpent;
}

std::string DCPc_serpent::getAlgorithm()
{
	return "serpent";
}

bool DCPc_serpent::selfTest()
{
	uint8_t key1[16] =
	{ 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
	uint8_t InData1[16] =
	{ 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01 };
	uint8_t OutData1[16] =
	{ 0xd5, 0xba, 0xa0, 0x0a, 0x4b, 0xb9, 0xd8, 0xa7, 0xc9, 0x81, 0xc8, 0xdc, 0x90, 0xd8, 0x9d, 0x92 };
	uint8_t Key2[24] =
	{ 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
	uint8_t InData2[16] =
	{ 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01 };
	uint8_t OutData2[16] =
	{ 0xda, 0x86, 0x08, 0x42, 0xb7, 0x20, 0x80, 0x2b, 0xf4, 0x04, 0xa4, 0xc7, 0x10, 0x34, 0x87, 0x9a };
	uint8_t Key3[32] =
	{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
	uint8_t InData3[16] =
	{ 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01 };
	uint8_t OutData3[16] =
	{ 0x93, 0xdf, 0x9a, 0x3c, 0xaf, 0xe3, 0x87, 0xbd, 0x99, 0x9e, 0xeb, 0xe3, 0x93, 0xa1, 0x7f, 0xca };

	uint8_t Block[16];

	memset(Block, 0, sizeof(Block));
	init(key1, sizeof(key1) * 8, nullptr);
	encryptECB(InData1, Block);
	bool result = memcmp(Block, OutData1, 16) == 0;
	decryptECB(Block, Block);
	burn();
	result = result && memcmp(Block, InData1, 16) == 0;
	init(Key2, sizeof(Key2) * 8, nullptr);
	encryptECB(InData2, Block);
	result = result && memcmp(Block, OutData2, 16) == 0;
	decryptECB(Block, Block);
	burn();
	result = result && memcmp(Block, InData2, 16) == 0;
	init(Key3, sizeof(Key3) * 8, nullptr);
	encryptECB(InData3, Block);
	result = result && memcmp(Block, OutData3, 16) == 0;
	decryptECB(Block, Block);
	burn();
	result = result && memcmp(Block, InData3, 16) == 0;
	//http://serpent.online-domain-tools.com/
	std::string strkey = "1234123412341234";
	std::string strplain = "1234567890";
	//std::vector<uint8_t> vcipher = fromHex("6743C3D1519AB4F2CD9A78AB09A511BD");
	init((uint8_t*)strkey.c_str(), strkey.length() * 8, nullptr);
	encryptECB((uint8_t*)strplain.c_str(), Block);
	//result = result && memcmp(Block, vcipher.data(), 16) == 0;
	//http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors

	std::vector<uint8_t> vkey = fromHex("8000000000000000000000000000000000000000000000000000000000000000");
	std::vector<uint8_t> vplain = fromHex("00000000000000000000000000000000");
	std::vector<uint8_t> vcipher = fromHex("A223AA1288463C0E2BE38EBD825616C0");
	init(vkey.data(), vkey.size() * 8, nullptr);
	encryptECB(vplain.data(), Block);
	result = result && memcmp(Block, vcipher.data(), 16) == 0;
	return result;
}


void DCPc_serpent::initKey(uint8_t *key, uint32_t size)
{
	uint32_t kp[140];
	int n;
	uint32_t t, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17;
	uint32_t a, b, c, d;

	memset(kp, 0, sizeof(kp));
	memmove(kp, key, size / 8);
	if (size < 256)
	{
		int i = size / 32;
		t = 1 << (size % 32);
		kp[i] = (kp[i] & (t - 1)) | t;
	};
	for (int i = 8; i<140; i++)
	{
		t = kp[i - 8] ^ kp[i - 5] ^ kp[i - 3] ^ kp[i - 1] ^ 0x9e3779b9 ^ uint32_t(i - 8);
		kp[i] = (t << 11) | (t >> 21);
	};
	for (int i = 0 ; i<4; i++)
	{
		n = i * 32;
		a = kp[n + 4 * 0 + 8]; b = kp[n + 4 * 0 + 9]; c = kp[n + 4 * 0 + 10]; d = kp[n + 4 * 0 + 11];
		t1 = a ^ c; t2 = a | d; t3 = a & b; t4 = a & d; t5 = b | t4; t6 = t1 & t2; kp[9 + n] = t5 ^ t6; t8 = b ^ d; t9 = c | t3; t10 = t6 ^ t8; kp[11 + n] = t9 ^ t10; t12 = c ^ t3; t13 = t2 & kp[11 + n]; kp[10 + n] = t12 ^ t13; t15 = ~ kp[10 + n]; t16 = t2 ^ t3; t17 = kp[9 + n] & t15; kp[8 + n] = t16 ^ t17;
		a = kp[n + 4 * 1 + 8]; b = kp[n + 4 * 1 + 9]; c = kp[n + 4 * 1 + 10]; d = kp[n + 4 * 1 + 11];
		t1 = ~ a; t2 = b ^ d; t3 = c & t1; kp[12 + n] = t2 ^ t3; t5 = c ^ t1; t6 = c ^ kp[12 + n]; t7 = b & t6; kp[15 + n] = t5 ^ t7; t9 = d | t7; t10 = kp[12 + n] | t5; t11 = t9 & t10; kp[14 + n] = a ^ t11; t13 = d | t1; t14 = t2 ^ kp[15 + n]; t15 = kp[14 + n] ^ t13; kp[13 + n] = t14 ^ t15;
		a = kp[n + 4 * 2 + 8]; b = kp[n + 4 * 2 + 9]; c = kp[n + 4 * 2 + 10]; d = kp[n + 4 * 2 + 11];
		t1 = a ^ d; t2 = b ^ d; t3 = a & b; t4 = ~ c; t5 = t2 ^ t3; kp[18 + n] = t4 ^ t5; t7 = a ^ t2; t8 = b | t4; t9 = d | kp[18 + n]; t10 = t7 & t9; kp[17 + n] = t8 ^ t10; t12 = c ^ d; t13 = t1 | t2; t14 = kp[17 + n] ^ t12; kp[19 + n] = t13 ^ t14; t16 = t1 | kp[18 + n]; t17 = t8 ^ t14; kp[16 + n] = t16 ^ t17;
		a = kp[n + 4 * 3 + 8]; b = kp[n + 4 * 3 + 9]; c = kp[n + 4 * 3 + 10]; d = kp[n + 4 * 3 + 11];
		t1 = b ^ d; t2 = ~ t1; t3 = a | d; t4 = b ^ c; kp[23 + n] = t3 ^ t4; t6 = a ^ b; t7 = a | t4; t8 = c & t6; t9 = t2 | t8; kp[20 + n] = t7 ^ t9; t11 = a ^ kp[23 + n]; t12 = t1 & t6; t13 = kp[20 + n] ^ t11; kp[21 + n] = t12 ^ t13; t15 = kp[20 + n] | kp[21 + n]; t16 = t3 & t15; kp[22 + n] = b ^ t16;
		a = kp[n + 4 * 4 + 8]; b = kp[n + 4 * 4 + 9]; c = kp[n + 4 * 4 + 10]; d = kp[n + 4 * 4 + 11];
		t1 = ~ c; t2 = b ^ c; t3 = b | t1; t4 = d ^ t3; t5 = a & t4; kp[27 + n] = t2 ^ t5; t7 = a ^ d; t8 = b ^ t5; t9 = t2 | t8; kp[25 + n] = t7 ^ t9; t11 = d & t3; t12 = t5 ^ kp[25 + n]; t13 = kp[27 + n] & t12; kp[26 + n] = t11 ^ t13; t15 = t1 | t4; t16 = t12 ^ kp[26 + n]; kp[24 + n] = t15 ^ t16;
		a = kp[n + 4 * 5 + 8]; b = kp[n + 4 * 5 + 9]; c = kp[n + 4 * 5 + 10]; d = kp[n + 4 * 5 + 11];
		t1 = a ^ c; t2 = b | d; t3 = b ^ c; t4 = ~ t3; t5 = a & d; kp[29 + n] = t4 ^ t5; t7 = b | c; t8 = d ^ t1; t9 = t7 & t8; kp[31 + n] = t2 ^ t9; t11 = t1 & t7; t12 = t4 ^ t8; t13 = kp[31 + n] & t11; kp[28 + n] = t12 ^ t13; t15 = t3 ^ t11; t16 = kp[31 + n] | t15; kp[30 + n] = t12 ^ t16;
		a = kp[n + 4 * 6 + 8]; b = kp[n + 4 * 6 + 9]; c = kp[n + 4 * 6 + 10]; d = kp[n + 4 * 6 + 11];
		t1 = ~ a; t2 = a ^ b; t3 = a ^ d; t4 = c ^ t1; t5 = t2 | t3; kp[32 + n] = t4 ^ t5; t7 = ~ d; t8 = kp[32 + n] & t7; kp[33 + n] = t2 ^ t8; t10 = b | kp[33 + n]; t11 = c | kp[32 + n]; t12 = t7 ^ t10; kp[35 + n] = t11 ^ t12; t14 = d | kp[33 + n]; t15 = t1 ^ t14; t16 = kp[32 + n] | kp[35 + n]; kp[34 + n] = t15 ^ t16;
		a = kp[n + 4 * 7 + 8]; b = kp[n + 4 * 7 + 9]; c = kp[n + 4 * 7 + 10]; d = kp[n + 4 * 7 + 11];
		t1 = ~ a; t2 = a ^ d; t3 = a ^ b; t4 = c ^ t1; t5 = t2 | t3; kp[36 + n] = t4 ^ t5; t7 = ~ kp[36 + n]; t8 = b | t7; kp[39 + n] = t2 ^ t8; t10 = a & kp[36 + n]; t11 = b ^ kp[39 + n]; t12 = t8 & t11; kp[38 + n] = t10 ^ t12; t14 = a | t7; t15 = t3 ^ t14; t16 = kp[39 + n] & kp[38 + n]; kp[37 + n] = t15 ^ t16;
	};
	a = kp[136]; b = kp[137]; c = kp[138]; d = kp[139];
	t1 = a ^ c; t2 = a | d; t3 = a & b; t4 = a & d; t5 = b | t4; t6 = t1 & t2; kp[137] = t5 ^ t6; t8 = b ^ d; t9 = c | t3; t10 = t6 ^ t8; kp[139] = t9 ^ t10; t12 = c ^ t3; t13 = t2 & kp[139]; kp[138] = t12 ^ t13; t15 = ~ kp[138]; t16 = t2 ^ t3; t17 = kp[137] & t15; kp[136] = t16 ^ t17;
	memmove(l_key, kp+8, sizeof(l_key));
	memset(kp, 0, sizeof(kp));
}

void DCPc_serpent::burn()
{
	memset(l_key, 0, sizeof(l_key));
	DCP_blockcipher128::burn();
}

void DCPc_serpent::encryptECB(uint8_t *inData, uint8_t *outData)
{
uint32_t a, b, c, d, e, f, g, h;
uint32_t t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17;

	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");

	a = *((uint32_t*)(inData));
	b = *((uint32_t*)(inData + 4) ) ;
	c = *((uint32_t*)(inData + 8) ) ;
	d = *((uint32_t*)(inData + 12) ) ;

	int i = 0;
	while (i < 32)
	{
		a = a ^ l_key[4 * (i)]; b = b ^ l_key[4 * (i)+1]; c = c ^ l_key[4 * (i)+2]; d = d ^ l_key[4 * (i)+3];
		t1 = b ^ d; t2 = ~ t1; t3 = a | d; t4 = b ^ c; h = t3 ^ t4; t6 = a ^ b; t7 = a | t4; t8 = c & t6; t9 = t2 | t8; e = t7 ^ t9; t11 = a ^ h; t12 = t1 & t6; t13 = e ^ t11; f = t12 ^ t13; t15 = e | f; t16 = t3 & t15; g = b ^ t16;
		e = (e << 13) | (e >> 19); g = (g << 3) | (g >> 29); f = f ^ e ^ g; h = h ^ g ^ (e << 3); f = (f << 1) | (f >> 31); h = (h << 7) | (h >> 25); e = e ^ f ^ h; g = g ^ h ^ (f << 7); e = (e << 5) | (e >> 27); g = (g << 22) | (g >> 10);
		e = e ^ l_key[4 * (i + 1)]; f = f ^ l_key[4 * (i + 1) + 1]; g = g ^ l_key[4 * (i + 1) + 2]; h = h ^ l_key[4 * (i + 1) + 3];
		t1 = e ^ h; t2 = f ^ h; t3 = e & f; t4 = ~ g; t5 = t2 ^ t3; c = t4 ^ t5; t7 = e ^ t2; t8 = f | t4; t9 = h | c; t10 = t7 & t9; b = t8 ^ t10; t12 = g ^ h; t13 = t1 | t2; t14 = b ^ t12; d = t13 ^ t14; t16 = t1 | c; t17 = t8 ^ t14; a = t16 ^ t17;
		a = (a << 13) | (a >> 19); c = (c << 3) | (c >> 29); b = b ^ a ^ c; d = d ^ c ^ (a << 3); b = (b << 1) | (b >> 31); d = (d << 7) | (d >> 25); a = a ^ b ^ d; c = c ^ d ^ (b << 7); a = (a << 5) | (a >> 27); c = (c << 22) | (c >> 10);
		a = a ^ l_key[4 * (i + 2)]; b = b ^ l_key[4 * (i + 2) + 1]; c = c ^ l_key[4 * (i + 2) + 2]; d = d ^ l_key[4 * (i + 2) + 3];
		t1 = ~ a; t2 = b ^ d; t3 = c & t1; e = t2 ^ t3; t5 = c ^ t1; t6 = c ^ e; t7 = b & t6; h = t5 ^ t7; t9 = d | t7; t10 = e | t5; t11 = t9 & t10; g = a ^ t11; t13 = d | t1; t14 = t2 ^ h; t15 = g ^ t13; f = t14 ^ t15;
		e = (e << 13) | (e >> 19); g = (g << 3) | (g >> 29); f = f ^ e ^ g; h = h ^ g ^ (e << 3); f = (f << 1) | (f >> 31); h = (h << 7) | (h >> 25); e = e ^ f ^ h; g = g ^ h ^ (f << 7); e = (e << 5) | (e >> 27); g = (g << 22) | (g >> 10);
		e = e ^ l_key[4 * (i + 3)]; f = f ^ l_key[4 * (i + 3) + 1]; g = g ^ l_key[4 * (i + 3) + 2]; h = h ^ l_key[4 * (i + 3) + 3];
		t1 = e ^ g; t2 = e | h; t3 = e & f; t4 = e & h; t5 = f | t4; t6 = t1 & t2; b = t5 ^ t6; t8 = f ^ h; t9 = g | t3; t10 = t6 ^ t8; d = t9 ^ t10; t12 = g ^ t3; t13 = t2 & d; c = t12 ^ t13; t15 = ~ c; t16 = t2 ^ t3; t17 = b & t15; a = t16 ^ t17;
		a = (a << 13) | (a >> 19); c = (c << 3) | (c >> 29); b = b ^ a ^ c; d = d ^ c ^ (a << 3); b = (b << 1) | (b >> 31); d = (d << 7) | (d >> 25); a = a ^ b ^ d; c = c ^ d ^ (b << 7); a = (a << 5) | (a >> 27); c = (c << 22) | (c >> 10);
		a = a ^ l_key[4 * (i + 4)]; b = b ^ l_key[4 * (i + 4) + 1]; c = c ^ l_key[4 * (i + 4) + 2]; d = d ^ l_key[4 * (i + 4) + 3];
		t1 = ~ a; t2 = a ^ d; t3 = a ^ b; t4 = c ^ t1; t5 = t2 | t3; e = t4 ^ t5; t7 = ~ e; t8 = b | t7; h = t2 ^ t8; t10 = a & e; t11 = b ^ h; t12 = t8 & t11; g = t10 ^ t12; t14 = a | t7; t15 = t3 ^ t14; t16 = h & g; f = t15 ^ t16;
		e = (e << 13) | (e >> 19); g = (g << 3) | (g >> 29); f = f ^ e ^ g; h = h ^ g ^ (e << 3); f = (f << 1) | (f >> 31); h = (h << 7) | (h >> 25); e = e ^ f ^ h; g = g ^ h ^ (f << 7); e = (e << 5) | (e >> 27); g = (g << 22) | (g >> 10);
		e = e ^ l_key[4 * (i + 5)]; f = f ^ l_key[4 * (i + 5) + 1]; g = g ^ l_key[4 * (i + 5) + 2]; h = h ^ l_key[4 * (i + 5) + 3];
		t1 = ~ e; t2 = e ^ f; t3 = e ^ h; t4 = g ^ t1; t5 = t2 | t3; a = t4 ^ t5; t7 = ~ h; t8 = a & t7; b = t2 ^ t8; t10 = f | b; t11 = g | a; t12 = t7 ^ t10; d = t11 ^ t12; t14 = h | b; t15 = t1 ^ t14; t16 = a | d; c = t15 ^ t16;
		a = (a << 13) | (a >> 19); c = (c << 3) | (c >> 29); b = b ^ a ^ c; d = d ^ c ^ (a << 3); b = (b << 1) | (b >> 31); d = (d << 7) | (d >> 25); a = a ^ b ^ d; c = c ^ d ^ (b << 7); a = (a << 5) | (a >> 27); c = (c << 22) | (c >> 10);
		a = a ^ l_key[4 * (i + 6)]; b = b ^ l_key[4 * (i + 6) + 1]; c = c ^ l_key[4 * (i + 6) + 2]; d = d ^ l_key[4 * (i + 6) + 3];
		t1 = a ^ c; t2 = b | d; t3 = b ^ c; t4 = ~ t3; t5 = a & d; f = t4 ^ t5; t7 = b | c; t8 = d ^ t1; t9 = t7 & t8; h = t2 ^ t9; t11 = t1 & t7; t12 = t4 ^ t8; t13 = h & t11; e = t12 ^ t13; t15 = t3 ^ t11; t16 = h | t15; g = t12 ^ t16;
		e = (e << 13) | (e >> 19); g = (g << 3) | (g >> 29); f = f ^ e ^ g; h = h ^ g ^ (e << 3); f = (f << 1) | (f >> 31); h = (h << 7) | (h >> 25); e = e ^ f ^ h; g = g ^ h ^ (f << 7); e = (e << 5) | (e >> 27); g = (g << 22) | (g >> 10);
		e = e ^ l_key[4 * (i + 7)]; f = f ^ l_key[4 * (i + 7) + 1]; g = g ^ l_key[4 * (i + 7) + 2]; h = h ^ l_key[4 * (i + 7) + 3];
		t1 = ~ g; t2 = f ^ g; t3 = f | t1; t4 = h ^ t3; t5 = e & t4; d = t2 ^ t5; t7 = e ^ h; t8 = f ^ t5; t9 = t2 | t8; b = t7 ^ t9; t11 = h & t3; t12 = t5 ^ b; t13 = d & t12; c = t11 ^ t13; t15 = t1 | t4; t16 = t12 ^ c; a = t15 ^ t16;

		i += 8;
		if (i < 32)
		{
			a = (a << 13) | (a >> 19); c = (c << 3) | (c >> 29); b = b ^ a ^ c; d = d ^ c ^ (a << 3); b = (b << 1) | (b >> 31); d = (d << 7) | (d >> 25); a = a ^ b ^ d; c = c ^ d ^ (b << 7); a = (a << 5) | (a >> 27); c = (c << 22) | (c >> 10);
		};
	};
	a = a ^ l_key[128]; b = b ^ l_key[128 + 1]; c = c ^ l_key[128 + 2]; d = d ^ l_key[128 + 3];

	*((uint32_t*)(outData + 0)) = a;
	*((uint32_t*)(outData + 4) ) = b;
	*((uint32_t*)(outData + 8) ) = c;
	*((uint32_t*)(outData + 12) ) = d;
};

void DCPc_serpent::decryptECB(uint8_t *inData, uint8_t *outData)
{
uint32_t a, b, c, d, e, f, g, h;
uint32_t t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16;

	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");

	a = *((uint32_t*)(inData));
	b = *((uint32_t*)(inData + 4) ) ;
	c = *((uint32_t*)(inData + 8) ) ;
	d = *((uint32_t*)(inData + 12) ) ;

	int i = 32;
	a = a ^ l_key[4 * 32]; b = b ^ l_key[4 * 32 + 1]; c = c ^ l_key[4 * 32 + 2]; d = d ^ l_key[4 * 32 + 3];
	while (i > 0)
	{
		if (i < 32)
		{
			c = (c >> 22) | (c << 10); a = (a >> 5) | (a << 27); c = c ^ d ^ (b << 7); a = a ^ b ^ d; d = (d >> 7) | (d << 25); b = (b >> 1) | (b << 31); d = d ^ c ^ (a << 3); b = b ^ a ^ c; c = (c >> 3) | (c << 29); a = (a >> 13) | (a << 19);
		};

		t1 = a & b; t2 = a | b; t3 = c | t1; t4 = d & t2; h = t3 ^ t4; t6 = ~ d; t7 = b ^ t4; t8 = h ^ t6; t9 = t7 | t8; f = a ^ t9; t11 = c ^ t7; t12 = d | f; e = t11 ^ t12; t14 = a & h; t15 = t3 ^ f; t16 = e ^ t14; g = t15 ^ t16;
		e = e ^ l_key[4 * (i - 1)]; f = f ^ l_key[4 * (i - 1) + 1]; g = g ^ l_key[4 * (i - 1) + 2]; h = h ^ l_key[4 * (i - 1) + 3];
		g = (g >> 22) | (g << 10); e = (e >> 5) | (e << 27); g = g ^ h ^ (f << 7); e = e ^ f ^ h; h = (h >> 7) | (h << 25); f = (f >> 1) | (f << 31); h = h ^ g ^ (e << 3); f = f ^ e ^ g; g = (g >> 3) | (g << 29); e = (e >> 13) | (e << 19);
		t1 = ~ g; t2 = e ^ g; t3 = f ^ h; t4 = e | t1; b = t3 ^ t4; t6 = e | f; t7 = f & t2; t8 = b ^ t6; t9 = t7 | t8; a = g ^ t9; t11 = ~ b; t12 = h | t2; t13 = t9 ^ t11; d = t12 ^ t13; t15 = f ^ t11; t16 = a & d; c = t15 ^ t16;
		a = a ^ l_key[4 * (i - 2)]; b = b ^ l_key[4 * (i - 2) + 1]; c = c ^ l_key[4 * (i - 2) + 2]; d = d ^ l_key[4 * (i - 2) + 3];
		c = (c >> 22) | (c << 10); a = (a >> 5) | (a << 27); c = c ^ d ^ (b << 7); a = a ^ b ^ d; d = (d >> 7) | (d << 25); b = (b >> 1) | (b << 31); d = d ^ c ^ (a << 3); b = b ^ a ^ c; c = (c >> 3) | (c << 29); a = (a >> 13) | (a << 19);
		t1 = ~ c; t2 = b & t1; t3 = d ^ t2; t4 = a & t3; t5 = b ^ t1; h = t4 ^ t5; t7 = b | h; t8 = a & t7; f = t3 ^ t8; t10 = a | d; t11 = t1 ^ t7; e = t10 ^ t11; t13 = a ^ c; t14 = b & t10; t15 = t4 | t13; g = t14 ^ t15;
		e = e ^ l_key[4 * (i - 3)]; f = f ^ l_key[4 * (i - 3) + 1]; g = g ^ l_key[4 * (i - 3) + 2]; h = h ^ l_key[4 * (i - 3) + 3];
		g = (g >> 22) | (g << 10); e = (e >> 5) | (e << 27); g = g ^ h ^ (f << 7); e = e ^ f ^ h; h = (h >> 7) | (h << 25); f = (f >> 1) | (f << 31); h = h ^ g ^ (e << 3); f = f ^ e ^ g; g = (g >> 3) | (g << 29); e = (e >> 13) | (e << 19);
		t1 = g ^ h; t2 = g | h; t3 = f ^ t2; t4 = e & t3; b = t1 ^ t4; t6 = e ^ h; t7 = f | h; t8 = t6 & t7; d = t3 ^ t8; t10 = ~ e; t11 = g ^ d; t12 = t10 | t11; a = t3 ^ t12; t14 = g | t4; t15 = t7 ^ t14; t16 = d | t10; c = t15 ^ t16;
		a = a ^ l_key[4 * (i - 4)]; b = b ^ l_key[4 * (i - 4) + 1]; c = c ^ l_key[4 * (i - 4) + 2]; d = d ^ l_key[4 * (i - 4) + 3];
		c = (c >> 22) | (c << 10); a = (a >> 5) | (a << 27); c = c ^ d ^ (b << 7); a = a ^ b ^ d; d = (d >> 7) | (d << 25); b = (b >> 1) | (b << 31); d = d ^ c ^ (a << 3); b = b ^ a ^ c; c = (c >> 3) | (c << 29); a = (a >> 13) | (a << 19);
		t1 = b ^ c; t2 = b | c; t3 = a ^ c; t4 = t2 ^ t3; t5 = d | t4; e = t1 ^ t5; t7 = a ^ d; t8 = t1 | t5; t9 = t2 ^ t7; g = t8 ^ t9; t11 = a & t4; t12 = e | t9; f = t11 ^ t12; t14 = a & g; t15 = t2 ^ t14; t16 = e & t15; h = t4 ^ t16;
		e = e ^ l_key[4 * (i - 5)]; f = f ^ l_key[4 * (i - 5) + 1]; g = g ^ l_key[4 * (i - 5) + 2]; h = h ^ l_key[4 * (i - 5) + 3];
		g = (g >> 22) | (g << 10); e = (e >> 5) | (e << 27); g = g ^ h ^ (f << 7); e = e ^ f ^ h; h = (h >> 7) | (h << 25); f = (f >> 1) | (f << 31); h = h ^ g ^ (e << 3); f = f ^ e ^ g; g = (g >> 3) | (g << 29); e = (e >> 13) | (e << 19);
		t1 = f ^ h; t2 = ~ t1; t3 = e ^ g; t4 = g ^ t1; t5 = f & t4; a = t3 ^ t5; t7 = e | t2; t8 = h ^ t7; t9 = t3 | t8; d = t1 ^ t9; t11 = ~ t4; t12 = a | d; b = t11 ^ t12; t14 = h & t11; t15 = t3 ^ t12; c = t14 ^ t15;
		a = a ^ l_key[4 * (i - 6)]; b = b ^ l_key[4 * (i - 6) + 1]; c = c ^ l_key[4 * (i - 6) + 2]; d = d ^ l_key[4 * (i - 6) + 3];
		c = (c >> 22) | (c << 10); a = (a >> 5) | (a << 27); c = c ^ d ^ (b << 7); a = a ^ b ^ d; d = (d >> 7) | (d << 25); b = (b >> 1) | (b << 31); d = d ^ c ^ (a << 3); b = b ^ a ^ c; c = (c >> 3) | (c << 29); a = (a >> 13) | (a << 19);
		t1 = a ^ d; t2 = a & b; t3 = b ^ c; t4 = a ^ t3; t5 = b | d; h = t4 ^ t5; t7 = c | t1; t8 = b ^ t7; t9 = t4 & t8; f = t1 ^ t9; t11 = ~ t2; t12 = h & f; t13 = t9 ^ t11; g = t12 ^ t13; t15 = a & d; t16 = c ^ t13; e = t15 ^ t16;
		e = e ^ l_key[4 * (i - 7)]; f = f ^ l_key[4 * (i - 7) + 1]; g = g ^ l_key[4 * (i - 7) + 2]; h = h ^ l_key[4 * (i - 7) + 3];
		g = (g >> 22) | (g << 10); e = (e >> 5) | (e << 27); g = g ^ h ^ (f << 7); e = e ^ f ^ h; h = (h >> 7) | (h << 25); f = (f >> 1) | (f << 31); h = h ^ g ^ (e << 3); f = f ^ e ^ g; g = (g >> 3) | (g << 29); e = (e >> 13) | (e << 19);
		t1 = e ^ h; t2 = g ^ h; t3 = ~ t2; t4 = e | f; c = t3 ^ t4; t6 = f ^ t1; t7 = g | t6; t8 = e ^ t7; t9 = t2 & t8; b = t6 ^ t9; t11 = ~ t8; t12 = f & h; t13 = b | t12; d = t11 ^ t13; t15 = t2 ^ t12; t16 = b | d; a = t15 ^ t16;
		a = a ^ l_key[4 * (i - 8)]; b = b ^ l_key[4 * (i - 8) + 1]; c = c ^ l_key[4 * (i - 8) + 2]; d = d ^ l_key[4 * (i - 8) + 3];
		i -= 8;
	};

	*((uint32_t*)(outData + 0) ) = a;
	*((uint32_t*)(outData + 4) ) = b;
	*((uint32_t*)(outData + 8)) = c;
	*((uint32_t*)(outData + 12) ) = d;
};

