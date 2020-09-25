#include "DCPc_blowfish.h"
#include "Exception.h"

using namespace dcpcrypt;

DCPc_blowfish::DCPc_blowfish()
{
}


DCPc_blowfish::~DCPc_blowfish()
{
}

#include "DCPc_blowfish_tabs.h"
DCPenum DCPc_blowfish::getId()
{
	return DCPenum::c_blowfish;
}

std::string DCPc_blowfish::getAlgorithm()
{
	return "blowfish";
}

int DCPc_blowfish::getMaxKeySize()
{
	return 448;
}

//https://www.schneier.com/code/vectors.txt
bool DCPc_blowfish::selfTest()
{
	uint8_t Key1[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t Key2[8] = { 0x7C, 0xA1, 0x10, 0x45, 0x4A, 0x1A, 0x6E, 0x57 };
	uint8_t InData1[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t InData2[8] = { 0x01, 0xA1, 0xD6, 0xD0, 0x39, 0x77, 0x67, 0x42 };
	uint8_t OutData1[8] = { 0x4E, 0xF9, 0x97, 0x45, 0x61, 0x98, 0xDD, 0x78 };
	uint8_t OutData2[8] = { 0x59, 0xC6, 0x82, 0x45, 0xEB, 0x05, 0x28, 0x2B };
	uint8_t Data[8];

	memset(Data, 0, sizeof(Data));
	init(Key1, sizeof(Key1) * 8, nullptr);
	encryptECB(InData1, Data);
	bool result = memcmp(Data, OutData1, sizeof(Data)) == 0;
	reset();
	decryptECB(Data, Data);
	result = memcmp(Data, InData1, sizeof(Data)) == 0 && result;
	burn();
	init(Key2, sizeof(Key2) * 8, nullptr);
	encryptECB(InData2, Data);
	result = memcmp(Data, OutData2, sizeof(Data)) == 0 && result;
	reset();
	decryptECB(Data, Data);
	result = memcmp(Data, InData2, sizeof(Data)) == 0 && result;
	burn();
	return result;
}

void DCPc_blowfish::initKey(uint8_t *key, uint32_t size)
{
	uint32_t i, k;
	uint32_t A;
	uint8_t *KeyB;
	uint8_t Block[8];

	memset(Block, 0, sizeof(Block));
	size = size / 8;
	KeyB = key;
	memmove(SBox, SBoxOrg, sizeof(SBox));
	memmove(PBox, PBoxOrg, sizeof(PBox));
	k = 0;
	for (i = 0; i<18; i++)
	{
		A = KeyB[(k + 3) % size];
		A += KeyB[(k + 2) % size] << 8;
		A += KeyB[(k + 1) % size] << 16;
		A += KeyB[k % size] << 24;
		PBox[i] = PBox[i] ^ A;
		k = (k + 4) % size;
	};
	memset(Block, 0, sizeof(Block));
	for (i = 0; i <= 8; i++)
	{
		encryptECB((uint8_t*)Block, (uint8_t*)Block);
		PBox[i * 2] = Block[3] + (Block[2] << 8) + (Block[1] << 16) + (Block[0] << 24);
		PBox[i * 2 + 1] = Block[7] + (Block[6] << 8) + (Block[5] << 16) + (Block[4] << 24);
	}
	for (k = 0; k<4; k++)
	{
		for (i = 0; i<128; i++)
		{
			encryptECB((uint8_t*)Block, (uint8_t*)Block);
			SBox[k][i * 2] = Block[3] + (Block[2] << 8) + (Block[1] << 16) + (Block[0] << 24);
			SBox[k][i * 2 + 1] = Block[7] + (Block[6] << 8) + (Block[5] << 16) + (Block[4] << 24);
		}
	}
}

void DCPc_blowfish::burn()
{
	memset(SBox, 0xff, sizeof(SBox));
	memset(PBox, 0xff, sizeof(PBox));
	DCP_blockcipher64::burn();
}


void DCPc_blowfish::encryptECB(uint8_t * inData, uint8_t * outData)
{
	uint32_t xL, xR;
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	xL = *((uint32_t*)inData);
	xR = *((uint32_t*)(inData + 4));
	xL = ((xL & 0xFF) << 24) | ((xL & 0xFF00) << 8) | ((xL & 0xFF0000) >> 8) | ((xL & 0xFF000000) >> 24);
	xR = ((xR & 0xFF) << 24) | ((xR & 0xFF00) << 8) | ((xR & 0xFF0000) >> 8) | ((xR & 0xFF000000) >> 24);
	xL = xL ^ PBox[0];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[1];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[2];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[3];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[4];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[5];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[6];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[7];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[8];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[9];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[10];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[11];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[12];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[13];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[14];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[15];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[16];
	xR = xR ^ PBox[17];
	xL = ((xL & 0xFF) << 24) | ((xL & 0xFF00) << 8) | ((xL & 0xFF0000) >> 8) | ((xL & 0xFF000000) >> 24);
	xR = ((xR & 0xFF) << 24) | ((xR & 0xFF00) << 8) | ((xR & 0xFF0000) >> 8) | ((xR & 0xFF000000) >> 24);
	*((uint32_t*)outData) = xR;
	*((uint32_t*)(outData + 4)) = xL;
}

void DCPc_blowfish::decryptECB(uint8_t * inData, uint8_t * outData)
{
	uint32_t xL, xR;
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");

	xL = *((uint32_t*)inData);
	xR = *((uint32_t*)(inData + 4));
	xL = (xL >> 24) | ((xL >> 8) & 0xFF00) | ((xL << 8) & 0xFF0000) | (xL << 24);
	xR = (xR >> 24) | ((xR >> 8) & 0xFF00) | ((xR << 8) & 0xFF0000) | (xR << 24);
	xL = xL ^ PBox[17];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[16];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[15];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[14];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[13];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[12];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[11];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[10];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[9];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[8];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[7];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[6];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[5];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[4];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[3];
	xR = xR ^ (((SBox[0][(xL >> 24) & 0xFF] + SBox[1][(xL >> 16) & 0xFF]) ^
		SBox[2][(xL >> 8) & 0xFF]) + SBox[3][xL & 0xFF]) ^ PBox[2];
	xL = xL ^ (((SBox[0][(xR >> 24) & 0xFF] + SBox[1][(xR >> 16) & 0xFF]) ^
		SBox[2][(xR >> 8) & 0xFF]) + SBox[3][xR & 0xFF]) ^ PBox[1];
	xR = xR ^ PBox[0];
	xL = (xL >> 24) | ((xL >> 8) & 0xFF00) | ((xL << 8) & 0xFF0000) | (xL << 24);
	xR = (xR >> 24) | ((xR >> 8) & 0xFF00) | ((xR << 8) & 0xFF0000) | (xR << 24);

	*((uint32_t*)outData) = xR;
	*((uint32_t*)(outData + 4)) = xL;
}