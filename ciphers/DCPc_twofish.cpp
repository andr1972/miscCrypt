#include "DCPc_twofish.h"
#include "DCPc_twofish_tabs.h"
#include "Exception.h"
#include "Util.h"
#include <vector>

using namespace dcpcrypt;

bool DCPc_twofish::MDSdone = false;
uint32_t DCPc_twofish::MDS[4][256];

uint32_t LFSR1(uint32_t x)
{
	if (x & 1)
		return  (x >> 1) ^ (MDS_GF_FDBK / 2);
	else
		return (x >> 1);
}
uint32_t LFSR2(uint32_t x)
{
	if (x & 2)
	{
		if (x & 1)
			return (x >> 2) ^ (MDS_GF_FDBK / 2) ^ (MDS_GF_FDBK / 4);
		else
			return (x >> 2) ^ (MDS_GF_FDBK / 2);
	}
	else
	{
		if (x & 1)
			return (x >> 2) ^ (MDS_GF_FDBK / 4);
		else
			return (x >> 2);
	}
}

uint32_t mul_X(uint32_t x)
{
	return x ^ LFSR2(x);
}

uint32_t mul_Y(uint32_t x)
{
	return x ^ LFSR1(x) ^ LFSR2(x);
}

DCPc_twofish::DCPc_twofish()
{
	if (!MDSdone)
	{
		preCompMDS();
		MDSdone = true;
	}
}

DCPc_twofish::~DCPc_twofish()
{
}

DCPenum DCPc_twofish::getId()
{
	return DCPenum::c_twofish;
}

std::string DCPc_twofish::getAlgorithm()
{
	return "twofish";
}

int DCPc_twofish::getMaxKeySize()
{
	return 256;
}

bool DCPc_twofish::selfTest()
{
	uint8_t Out128[16] =
	{ 0x5D, 0x9D, 0x4E, 0xEF, 0xFA, 0x91, 0x51, 0x57, 0x55, 0x24, 0xF1, 0x15, 0x81, 0x5A, 0x12, 0xE0 };
	uint8_t Out192[16] =
	{ 0xE7, 0x54, 0x49, 0x21, 0x2B, 0xEE, 0xF9, 0xF4, 0xA3, 0x90, 0xBD, 0x86, 0x0A, 0x64, 0x09, 0x41 };
	uint8_t Out256[16] =
	{ 0x37, 0xFE, 0x26, 0xFF, 0x1C, 0xF6, 0x61, 0x75, 0xF5, 0xDD, 0xF4, 0xC3, 0x3B, 0x97, 0xA2, 0x05 };

	uint8_t Key[32];
	uint8_t Block[16];

	//https://www.schneier.com/code/ecb_ival.txt
	std::vector<uint8_t> vkey = fromHex("00000000000000000000000000000000");
	std::vector<uint8_t> vplain = fromHex("00000000000000000000000000000000");
	std::vector<uint8_t> vcipher = fromHex("9F589F5CF6122C32B6BFEC2F2AE8C35A");
	init(vkey.data(), vkey.size() * 8, nullptr);
	encryptECB(vplain.data(), Block);
	burn();
	bool result = memcmp(Block, vcipher.data(), 16) == 0;

	uint8_t in128[16] =
	{ 0x5D, 0x9D, 0x4f, 0xEF, 0xFA, 0x91, 0x51, 0x57, 0x55, 0x24, 0xF1, 0x15, 0x81, 0x5A, 0x12, 0xE0 };
	uint8_t key128[16] =
	{ 0x5D, 0x9D, 0x4f, 0xEF, 0xFB, 0x91, 0x51, 0x57, 0x55, 0x24, 0xF1, 0x15, 0x81, 0x5A, 0x12, 0xE0 };
	//test decoding
	init(key128, 128, nullptr);
	encryptECB(in128, Block);
	decryptECB(Block, Block);
	result = result && memcmp(Block, in128, 16) == 0;

	memset(Key, 0, sizeof(Key));
	memset(Block, 0, sizeof(Block));
	for (int i = 1; i <= 49; i++)
	{
		init(Key, 128, nullptr);
		memmove(Key, Block, 16);
		encryptECB(Block, Block);
		burn();
	}
	result = result && memcmp(Block, Out128, 16) == 0;
	memset(Key, 0, sizeof(Key));
	memset(Block, 0, sizeof(Block));
	for (int i = 1; i <= 49; i++)
	{
		init(Key, 192, nullptr);
		memmove(Key + 16, Key, 8);
		memmove(Key, Block, 16);
		encryptECB(Block, Block);
		burn();
	}
	result = result & memcmp(Block, Out192, 16) == 0;
	memset(Key, 0, sizeof(Key));
	memset(Block, 0, sizeof(Block));
	for (int i = 1; i <= 49; i++)
	{
		init(Key, 256, nullptr);
		memmove(Key + 16, Key, 16);
		memmove(Key, Block, 16);
		encryptECB(Block, Block);
		burn();
	}
	result = result & memcmp(Block, Out256, 16) == 0;
	burn();
	return result;
}

uint32_t RS_MDS_Encode(uint32_t lK0, uint32_t lK1)
{
	uint32_t lR, nJ, lG2, lG3;
	uint8_t bB;

	lR = lK1;
	for (nJ = 0; nJ < 4; nJ++)
	{
		bB = lR >> 24;
		if (bB & 0x80)
			lG2 = ((bB << 1) ^ RS_GF_FDBK) & 0xFF;
		else
			lG2 = (bB << 1) & 0xFF;
		if (bB & 1)
			lG3 = ((bB >> 1) & 0x7f) ^ (RS_GF_FDBK >> 1) ^ lG2;
		else
			lG3 = ((bB >> 1) & 0x7f) ^ lG2;
		lR = (lR << 8) ^ (lG3 << 24) ^ (lG2 << 16) ^ (lG3 << 8) ^ bB;
	}
	lR = lR ^ lK0;
	for (nJ = 0; nJ < 4; nJ++)
	{
		bB = lR >> 24;
		if (bB & 0x80)
			lG2 = ((bB << 1) ^ RS_GF_FDBK) & 0xFF;
		else
			lG2 = (bB << 1) & 0xFF;
		if (bB & 1)
			lG3 = ((bB >> 1) & 0x7f) ^ (RS_GF_FDBK >> 1) ^ lG2;
		else
			lG3 = ((bB >> 1) & 0x7f) ^ lG2;
		lR = (lR << 8) ^ (lG3 << 24) ^ (lG2 << 16) ^ (lG3 << 8) ^ bB;
	}
	return lR;
}

uint32_t DCPc_twofish::f32(uint32_t x, uint32_t *K32, uint32_t Len)
{
	uint32_t t0, t1, t2, t3;

	t0 = x & 0xFF;
	t1 = (x >> 8) & 0xFF;
	t2 = (x >> 16) & 0xFF;
	t3 = x >> 24;
	if (Len == 256)
	{
		t0 = p8x8[1][t0] ^ ((K32[3]) & 0xFF);
		t1 = p8x8[0][t1] ^ ((K32[3] >> 8) & 0xFF);
		t2 = p8x8[0][t2] ^ ((K32[3] >> 16) & 0xFF);
		t3 = p8x8[1][t3] ^ ((K32[3] >> 24));
	}
	if (Len >= 192)
	{
		t0 = p8x8[1][t0] ^ ((K32[2]) & 0xFF);
		t1 = p8x8[1][t1] ^ ((K32[2] >> 8) & 0xFF);
		t2 = p8x8[0][t2] ^ ((K32[2] >> 16) & 0xFF);
		t3 = p8x8[0][t3] ^ ((K32[2] >> 24));
	}
	return MDS[0][p8x8[0][p8x8[0][t0] ^ ((K32[1]) & 0xFF)] ^ ((K32[0]) & 0xFF)] ^
		MDS[1][p8x8[0][p8x8[1][t1] ^ ((K32[1] >> 8) & 0xFF)] ^ ((K32[0] >> 8) & 0xFF)] ^
		MDS[2][p8x8[1][p8x8[0][t2] ^ ((K32[1] >> 16) & 0xFF)] ^ ((K32[0] >> 16) & 0xFF)] ^
		MDS[3][p8x8[1][p8x8[1][t3] ^ ((K32[1] >> 24))] ^ ((K32[0] >> 24))];
}

void xor256(uint32_t *Dst, uint32_t *Src, uint8_t v)
{
	uint32_t i = 0;
	uint32_t j = v * 0x01010101;
	while (i<64)
	{
		Dst[i] = Src[i] ^ j;
		Dst[i + 1] = Src[i + 1] ^ j;
		Dst[i + 2] = Src[i + 2] ^ j;
		Dst[i + 3] = Src[i + 3] ^ j;
		i += 4;
	}
}

void DCPc_twofish::initKey(uint8_t *key, uint32_t size)
{
	const int subkeyCnt = ROUNDSUBKEYS + 2 * NUMROUNDS;

	uint32_t key32[8];
	uint32_t k32e[4], k32o[4], sboxKeys[4];
	uint32_t k64Cnt, A, B, q;
	uint8_t L0[256], L1[256];

	memset(key32, 0, sizeof(key32));
	memmove(key32, key, size / 8);
	if (size <= 128) // pad the key to either 128bit, 192bit | 256bit
		size = 128;
	else if (size <= 192)
		size = 192;
	else
		size = 256;
	k64Cnt = size / 64;
	int j = k64Cnt - 1;
	int initj = j;
	for (int i = 0; i <= initj; i++)
	{
		k32e[i] = key32[2 * i];
		k32o[i] = key32[2 * i + 1];
		sboxKeys[j] = RS_MDS_Encode(k32e[i], k32o[i]);
		j--;
	}
	q = 0;
	for (int i = 0; i<subkeyCnt / 2; i++)
	{
		A = f32(q, k32e, size);
		B = f32(q + SK_BUMP, k32o, size);
		B = (B << 8) | (B >> 24);
		subKeys[2 * i] = A + B;
		B = A + 2 * B;
		subKeys[2 * i + 1] = (B << SK_ROTL) | (B >> (32 - SK_ROTL));
		q += SK_STEP;
	}
	switch (size)
	{
	case 128: {
		xor256((uint32_t *)L0, (uint32_t *)p8x8[0], sboxKeys[1] & 0xFF);
		A = (sboxKeys[0] & 0xFF);
		int i = 0;
		while (i < 256)
		{
			sBox[0 & 2][2 * i + (0 & 1)] = MDS[0][p8x8[0][L0[i]] ^ A];
			sBox[0 & 2][2 * i + (0 & 1) + 2] = MDS[0][p8x8[0][L0[i + 1]] ^ A];
			i += 2;
		}
		xor256((uint32_t *)L0, (uint32_t *)p8x8[1], (sboxKeys[1] >> 8) & 0xFF);
		A = (sboxKeys[0] >> 8) & 0xFF;
		i = 0;
		while (i < 256)
		{
			sBox[1 & 2][2 * i + (1 & 1)] = MDS[1][p8x8[0][L0[i]] ^ A];
			sBox[1 & 2][2 * i + (1 & 1) + 2] = MDS[1][p8x8[0][L0[i + 1]] ^ A];
			i += 2;
		}
		xor256((uint32_t *)L0, (uint32_t *)p8x8[0], (sboxKeys[1] >> 16) & 0xFF);
		A = (sboxKeys[0] >> 16) & 0xFF;
		i = 0;
		while (i < 256)
		{
			sBox[2 & 2][2 * i + (2 & 1)] = MDS[2][p8x8[1][L0[i]] ^ A];
			sBox[2 & 2][2 * i + (2 & 1) + 2] = MDS[2][p8x8[1][L0[i + 1]] ^ A];
			i += 2;
		}
		xor256((uint32_t *)L0, (uint32_t *)p8x8[1], (sboxKeys[1] >> 24));
		A = (sboxKeys[0] >> 24);
		i = 0;
		while (i < 256)
		{
			sBox[3 & 2][2 * i + (3 & 1)] = MDS[3][p8x8[1][L0[i]] ^ A];
			sBox[3 & 2][2 * i + (3 & 1) + 2] = MDS[3][p8x8[1][L0[i + 1]] ^ A];
			i += 2;
		}
	}
			  break;
	case 192: {
		xor256((uint32_t *)L0, (uint32_t *)p8x8[1], sboxKeys[2] & 0xFF);
		A = sboxKeys[0] & 0xFF;
		B = sboxKeys[1] & 0xFF;
		int i = 0;
		while (i < 256)
		{
			sBox[0 & 2][2 * i + (0 & 1)] = MDS[0][p8x8[0][p8x8[0][L0[i]] ^ B] ^ A];
			sBox[0 & 2][2 * i + (0 & 1) + 2] = MDS[0][p8x8[0][p8x8[0][L0[i + 1]] ^ B] ^ A];
			i += 2;
		}
		xor256((uint32_t *)L0, (uint32_t *)p8x8[1], (sboxKeys[2] >> 8) & 0xFF);
		A = (sboxKeys[0] >> 8) & 0xFF;
		B = (sboxKeys[1] >> 8) & 0xFF;
		i = 0;
		while (i < 256)
		{
			sBox[1 & 2][2 * i + (1 & 1)] = MDS[1][p8x8[0][p8x8[1][L0[i]] ^ B] ^ A];
			sBox[1 & 2][2 * i + (1 & 1) + 2] = MDS[1][p8x8[0][p8x8[1][L0[i + 1]] ^ B] ^ A];
			i += 2;
		}
		xor256((uint32_t *)L0, (uint32_t *)p8x8[0], (sboxKeys[2] >> 16) & 0xFF);
		A = (sboxKeys[0] >> 16) & 0xFF;
		B = (sboxKeys[1] >> 16) & 0xFF;
		i = 0;
		while (i < 256)
		{
			sBox[2 & 2][2 * i + (2 & 1)] = MDS[2][p8x8[1][p8x8[0][L0[i]] ^ B] ^ A];
			sBox[2 & 2][2 * i + (2 & 1) + 2] = MDS[2][p8x8[1][p8x8[0][L0[i + 1]] ^ B] ^ A];
			i += 2;
		}
		xor256((uint32_t *)L0, (uint32_t *)p8x8[0], (sboxKeys[2] >> 24));
		A = (sboxKeys[0] >> 24);
		B = (sboxKeys[1] >> 24);
		i = 0;
		while (i < 256)
		{
			sBox[3 & 2][2 * i + (3 & 1)] = MDS[3][p8x8[1][p8x8[1][L0[i]] ^ B] ^ A];
			sBox[3 & 2][2 * i + (3 & 1) + 2] = MDS[3][p8x8[1][p8x8[1][L0[i + 1]] ^ B] ^ A];
			i += 2;
		}
	}
			  break;
	case 256: {
		xor256((uint32_t *)L1, (uint32_t *)p8x8[1], (sboxKeys[3]) & 0xFF);
		int i = 0;
		while (i < 256)
		{
			L0[i] = p8x8[1][L1[i]];
			L0[i + 1] = p8x8[1][L1[i + 1]];
			i += 2;
		}
		xor256((uint32_t *)L0, (uint32_t *)L0, (sboxKeys[2]) & 0xFF);
		A = (sboxKeys[0]) & 0xFF;
		B = (sboxKeys[1]) & 0xFF;
		i = 0;
		while (i < 256)
		{
			sBox[0 & 2][2 * i + (0 & 1)] = MDS[0][p8x8[0][p8x8[0][L0[i]] ^ B] ^ A];
			sBox[0 & 2][2 * i + (0 & 1) + 2] = MDS[0][p8x8[0][p8x8[0][L0[i + 1]] ^ B] ^ A];
			i += 2;
		}
		xor256((uint32_t *)L1, (uint32_t *)p8x8[0], (sboxKeys[3] >> 8) & 0xFF);
		i = 0;
		while (i < 256)
		{
			L0[i] = p8x8[1][L1[i]];
			L0[i + 1] = p8x8[1][L1[i + 1]];
			i += 2;
		}
		xor256((uint32_t *)L0, (uint32_t *)L0, (sboxKeys[2] >> 8) & 0xFF);
		A = (sboxKeys[0] >> 8) & 0xFF;
		B = (sboxKeys[1] >> 8) & 0xFF;
		i = 0;
		while (i < 256)
		{
			sBox[1 & 2][2 * i + (1 & 1)] = MDS[1][p8x8[0][p8x8[1][L0[i]] ^ B] ^ A];
			sBox[1 & 2][2 * i + (1 & 1) + 2] = MDS[1][p8x8[0][p8x8[1][L0[i + 1]] ^ B] ^ A];
			i += 2;
		}

		xor256((uint32_t *)L1, (uint32_t *)p8x8[0], (sboxKeys[3] >> 16) & 0xFF);
		i = 0;
		while (i < 256)
		{
			L0[i] = p8x8[0][L1[i]];
			L0[i + 1] = p8x8[0][L1[i + 1]];
			i += 2;
		}
		xor256((uint32_t *)L0, (uint32_t *)L0, (sboxKeys[2] >> 16) & 0xFF);
		A = (sboxKeys[0] >> 16) & 0xFF;
		B = (sboxKeys[1] >> 16) & 0xFF;
		i = 0;
		while (i < 256)
		{
			sBox[2 & 2][2 * i + (2 & 1)] = MDS[2][p8x8[1][p8x8[0][L0[i]] ^ B] ^ A];
			sBox[2 & 2][2 * i + (2 & 1) + 2] = MDS[2][p8x8[1][p8x8[0][L0[i + 1]] ^ B] ^ A];
			i += 2;
		}
		xor256((uint32_t *)L1, (uint32_t *)p8x8[1], (sboxKeys[3] >> 24));
		i = 0;
		while (i < 256)
		{
			L0[i] = p8x8[0][L1[i]];
			L0[i + 1] = p8x8[0][L1[i + 1]];
			i += 2;
		}
		xor256((uint32_t *)L0, (uint32_t *)L0, (sboxKeys[2] >> 24));
		A = (sboxKeys[0] >> 24);
		B = (sboxKeys[1] >> 24);
		i = 0;
		while (i < 256)
		{
			sBox[3 & 2][2 * i + (3 & 1)] = MDS[3][p8x8[1][p8x8[1][L0[i]] ^ B] ^ A];
			sBox[3 & 2][2 * i + (3 & 1) + 2] = MDS[3][p8x8[1][p8x8[1][L0[i + 1]] ^ B] ^ A];
			i += 2;
		}

	}
			  break;
	}
}


void DCPc_twofish::burn()
{
	memset(sBox, 0xFF, sizeof(sBox));
	memset(subKeys, 0xFF, sizeof(subKeys));
	DCP_blockcipher128::burn();
}

void DCPc_twofish::encryptECB(uint8_t * inData, uint8_t * outData)
{
	uint32_t t0, t1;
	uint32_t x[4];

	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	x[0] = *((uint32_t*)(inData)) ^ subKeys[INPUTWHITEN];
	x[1] = *((uint32_t*)(inData + 4)) ^ subKeys[INPUTWHITEN + 1];
	x[2] = *((uint32_t*)(inData + 8)) ^ subKeys[INPUTWHITEN + 2];
	x[3] = *((uint32_t*)(inData + 12)) ^ subKeys[INPUTWHITEN + 3];
	int i = 0;
	while (i <= NUMROUNDS - 2)
	{
		t0 = sBox[0][ (x[0] << 1) & 0x1fe] ^ sBox[0][ ((x[0] >> 7) & 0x1fe) + 1]
			^ sBox[2][ (x[0] >> 15) & 0x1fe] ^ sBox[2][ ((x[0] >> 23) & 0x1fe) + 1];
		t1 = sBox[0][ ((x[1] >> 23) & 0x1fe)] ^ sBox[0][ ((x[1] << 1) & 0x1fe) + 1]
			^ sBox[2][ ((x[1] >> 7) & 0x1fe)] ^ sBox[2][ ((x[1] >> 15) & 0x1fe) + 1];
		x[3] = (x[3] << 1) | (x[3] >> 31);
		x[2] = x[2] ^ (t0 + t1 + subKeys[ROUNDSUBKEYS + 2 * i]);
		x[3] = x[3] ^ (t0 + 2 * t1 + subKeys[ROUNDSUBKEYS + 2 * i + 1]);
		x[2] = (x[2] >> 1) | (x[2] << 31);

		t0 = sBox[0][ (x[2] << 1) & 0x1fe] ^ sBox[0][ ((x[2] >> 7) & 0x1fe) + 1]
			^ sBox[2][ ((x[2] >> 15) & 0x1fe)] ^ sBox[2][ ((x[2] >> 23) & 0x1fe) + 1];
		t1 = sBox[0][ ((x[3] >> 23) & 0x1fe)] ^ sBox[0][ ((x[3] << 1) & 0x1fe) + 1]
			^ sBox[2][ ((x[3] >> 7) & 0x1fe)] ^ sBox[2][ ((x[3] >> 15) & 0x1fe) + 1];
		x[1] = (x[1] << 1) | (x[1] >> 31);
		x[0] = x[0] ^ (t0 + t1 + subKeys[ROUNDSUBKEYS + 2 * (i + 1)]);
		x[1] = x[1] ^ (t0 + 2 * t1 + subKeys[ROUNDSUBKEYS + 2 * (i + 1) + 1]);
		x[0] = (x[0] >> 1) | (x[0] << 31);
		i += 2;
	}
	*((uint32_t*)(outData + 0)) = x[2] ^ subKeys[OUTPUTWHITEN];
	*((uint32_t*)(outData + 4)) = x[3] ^ subKeys[OUTPUTWHITEN + 1];
	*((uint32_t*)(outData + 8)) = x[0] ^ subKeys[OUTPUTWHITEN + 2];
	*((uint32_t*)(outData + 12)) = x[1] ^ subKeys[OUTPUTWHITEN + 3];
}

void DCPc_twofish::decryptECB(uint8_t * inData, uint8_t * outData)
{
	uint32_t t0, t1;
	uint32_t x[4];

	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");

	x[2] = *((uint32_t*)inData) ^ subKeys[OUTPUTWHITEN];
	x[3] = *((uint32_t*)(inData + 4)) ^ subKeys[OUTPUTWHITEN + 1];
	x[0] = *((uint32_t*)(inData + 8)) ^ subKeys[OUTPUTWHITEN + 2];
	x[1] = *((uint32_t*)(inData + 12)) ^ subKeys[OUTPUTWHITEN + 3];
	int i = NUMROUNDS - 2;
	while (i >= 0)
	{
		t0 = sBox[0][ (x[2] << 1) & 0x1fe] ^ sBox[0][ ((x[2] >> 7) & 0x1fe) + 1]
			^ sBox[2][ ((x[2] >> 15) & 0x1fe)] ^ sBox[2][ ((x[2] >> 23) & 0x1fe) + 1];
		t1 = sBox[0][ ((x[3] >> 23) & 0x1fe)] ^ sBox[0][ ((x[3] << 1) & 0x1fe) + 1]
			^ sBox[2][ ((x[3] >> 7) & 0x1fe)] ^ sBox[2][ ((x[3] >> 15) & 0x1fe) + 1];
		x[0] = (x[0] << 1) | (x[0] >> 31);
		x[0] = x[0] ^ (t0 + t1 + subKeys[ROUNDSUBKEYS + 2 * (i + 1)]);
		x[1] = x[1] ^ (t0 + 2 * t1 + subKeys[ROUNDSUBKEYS + 2 * (i + 1) + 1]);
		x[1] = (x[1] >> 1) | (x[1] << 31);

		t0 = sBox[0][ (x[0] << 1) & 0x1fe] ^ sBox[0][ ((x[0] >> 7) & 0x1fe) + 1]
			^ sBox[2][ (x[0] >> 15) & 0x1fe] ^ sBox[2][ ((x[0] >> 23) & 0x1fe) + 1];
		t1 = sBox[0][ ((x[1] >> 23) & 0x1fe)] ^ sBox[0][ ((x[1] << 1) & 0x1fe) + 1]
			^ sBox[2][ ((x[1] >> 7) & 0x1fe)] ^ sBox[2][ ((x[1] >> 15) & 0x1fe) + 1];
		x[2] = (x[2] << 1) | (x[2] >> 31);
		x[2] = x[2] ^ (t0 + t1 + subKeys[ROUNDSUBKEYS + 2 * i]);
		x[3] = x[3] ^ (t0 + 2 * t1 + subKeys[ROUNDSUBKEYS + 2 * i + 1]);
		x[3] = (x[3] >> 1) | (x[3] << 31);
		i-=2;
	}
	*((uint32_t*)(outData + 0)) = x[0] ^ subKeys[INPUTWHITEN];
	*((uint32_t*)(outData + 4)) = x[1] ^ subKeys[INPUTWHITEN + 1];
	*((uint32_t*)(outData + 8)) = x[2] ^ subKeys[INPUTWHITEN + 2];
	*((uint32_t*)(outData + 12)) = x[3] ^ subKeys[INPUTWHITEN + 3];
}

void DCPc_twofish::preCompMDS()
{
	uint32_t m1[2], mx[2], my[2];

	for (uint32_t nI = 0; nI < 256; nI++)
	{
		m1[0] = p8x8[0][nI];
		mx[0] = mul_X(m1[0]);
		my[0] = mul_Y(m1[0]);
		m1[1] = p8x8[1][nI];
		mx[1] = mul_X(m1[1]);
		my[1] = mul_Y(m1[1]);
		MDS[0][nI] = (m1[1] << 0) |
			(mx[1] << 8) |
			(my[1] << 16) |
			(my[1] << 24);
		MDS[1][nI] = (my[0] << 0) |
			(my[0] << 8) |
			(mx[0] << 16) |
			(m1[0] << 24);
		MDS[2][nI] = (mx[1] << 0) |
			(my[1] << 8) |
			(m1[1] << 16) |
			(my[1] << 24);
		MDS[3][nI] = (mx[0] << 0) |
			(m1[0] << 8) |
			(my[0] << 16) |
			(mx[0] << 24);
	}
}
