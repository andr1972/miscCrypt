#include "DCP_blockcipher64.h"
#include "Exception.h"
#include "Util.h"

using namespace dcpcrypt;

DCP_blockcipher64::DCP_blockcipher64()
{
}


DCP_blockcipher64::~DCP_blockcipher64()
{
}

void DCP_blockcipher64::incCounter()
{
	CV[7]++;
	int i = 7;
	while (i > 0 && CV[i] == 0)
	{
		CV[i - 1]++;
		i--;
	}
}

void DCP_blockcipher64::init(uint8_t *key, uint32_t size, const char * initVector)
{
	DCP_cipher::init(key, size, initVector);
	initKey(key, size);
	if (!initVector)
	{
#ifdef DCP1COMPAT
#define FILLBYTE 0xFF
#else
#define FILLBYTE 0x00
#endif
		memset(IV, FILLBYTE, 8);
		encryptECB(IV, IV);
		reset();
	}
	else
	{
		memmove(IV, initVector, 8);
		reset();
	}
}

void DCP_blockcipher64::setIV(const char * value)
{
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	memmove(IV, value, 8);
	reset();
}

void DCP_blockcipher64::getIV(char * value)
{
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	memmove(value, CV, 8);
}

void DCP_blockcipher64::reset()
{
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	else
		memmove(CV, IV, 8);
}

void DCP_blockcipher64::burn()
{
	memset(IV, 0xFF, 8);
	memset(CV, 0xFF, 8);
}

void DCP_blockcipher64::encryptCBC(uint8_t *inData, uint8_t *outData, uint32_t size)
{
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	uint8_t *p1 = inData;
	uint8_t *p2 = outData;
	for (int i = 0; i < size / 8; i++)
	{
		memmove(p2, p1, 8);
		xorBlock(p2, CV, 8);
		encryptECB(p2, p2);
		memmove(CV, p2, 8);
		p1 += 8;
		p2 += 8;
	};
	if (size % 8 != 0)
	{
		encryptECB(CV, CV);
		memmove(p2, p1, size % 8);
		xorBlock(p2, CV, size % 8);
	};
}

void DCP_blockcipher64::decryptCBC(uint8_t *inData, uint8_t *outData, uint32_t size)
{
	uint8_t temp[8];
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	memset(temp, 0, sizeof(temp));
	uint8_t *p1 = inData;
	uint8_t *p2 = outData;
	for (int i = 0; i < size / 8; i++)
	{
		memmove(p2, p1, 8);
		memmove(temp, p1, 8);
		decryptECB(p2, p2);
		xorBlock(p2, CV, 8);
		memmove(CV, temp, 8);
		p1 += 8;
		p2 += 8;
	};
	if (size % 8 != 0)
	{
		encryptECB(CV, CV);
		memmove(p2, p1, size % 8);
		xorBlock(p2, CV, size % 8);
	};
};

void DCP_blockcipher64::encryptCFB8bit(uint8_t *inData, uint8_t *outData, uint32_t size)
{
	uint8_t temp[8];
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	uint8_t *p1 = inData;
	uint8_t *p2 = outData;
	memset(temp, 0, sizeof(temp));
	for (int i = 0; i<size; i++)
	{
		encryptECB(CV, temp);
		*p2 = *p1 ^ temp[0];
		memmove(CV, CV + 1, 8 - 1);
		CV[7] = *p2;
		p1++;
		p2++;
	};
}

void DCP_blockcipher64::decryptCFB8bit(uint8_t *inData, uint8_t *outData, uint32_t size)
{
	uint8_t tempByte;
	uint8_t temp[8];

	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	uint8_t *p1 = inData;
	uint8_t *p2 = outData;
	memset(temp, 0, sizeof(temp));
	for (int i = 0; i<size; i++)
	{
		tempByte = *p1;
		encryptECB(CV, temp);
		*p2 = *p1 ^ temp[0];
		memmove(CV, CV + 1, 8 - 1);
		CV[7] = tempByte;
		p1++;
		p2++;
	};
}

void DCP_blockcipher64::encryptCFBblock(uint8_t *inData, uint8_t *outData, uint32_t size)
{
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	uint8_t *p1 = inData;
	uint8_t *p2 = outData;
	for (int i = 0; i < size / 8; i++)
	{
		encryptECB(CV, CV);
		memmove(p2, p1, 8);
		xorBlock(p2, CV, 8);
		memmove(CV, p2, 8);
		p1 += 8;
		p2 += 8;
	};
	if ((size % 8) != 0)
	{
		encryptECB(CV, CV);
		memmove(p2, p1, size % 8);
		xorBlock(p2, CV, size % 8);
	};
}

void DCP_blockcipher64::decryptCFBblock(uint8_t *inData, uint8_t *outData, uint32_t size)
{

	uint8_t temp[8];

	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	uint8_t *p1 = inData;
	uint8_t *p2 = outData;
	memset(temp, 0, sizeof(temp));
	for (int i = 0; i < size / 8; i++)
	{
		memmove(temp, p1, 8);
		encryptECB(CV, CV);
		memmove(p2, p1, 8);
		xorBlock(p2, CV, 8);
		memmove(CV, temp, 8);
		p1 += 8;
		p2 += 8;
	};
	if ((size % 8) != 0)
	{
		encryptECB(CV, CV);
		memmove(p2, p1, size % 8);
		xorBlock(p2, CV, size % 8);
	};
}

void DCP_blockcipher64::encryptOFB(uint8_t *inData, uint8_t *outData, uint32_t size)
{

	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	uint8_t *p1 = inData;
	uint8_t *p2 = outData;
	for (int i = 0; i < size / 8; i++)
	{
		encryptECB(CV, CV);
		memmove(p2, p1, 8);
		xorBlock(p2, CV, 8);
		p1 += 8;
		p2 += 8;
	};
	if ((size % 8) != 0)
	{
		encryptECB(CV, CV);
		memmove(p2, p1, size % 8);
		xorBlock(p2, CV, size % 8);
	};
}

void DCP_blockcipher64::decryptOFB(uint8_t *inData, uint8_t *outData, uint32_t size)
{
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	uint8_t *p1 = inData;
	uint8_t *p2 = outData;
	for (int i = 0; i < size / 8; i++)
	{
		encryptECB(CV, CV);
		memmove(p2, p1, 8);
		xorBlock(p2, CV, 8);
		p1 += 8;
		p2 += 8;
	};
	if ((size % 8) != 0)
	{
		encryptECB(CV, CV);
		memmove(p2, p1, size % 8);
		xorBlock(p2, CV, size % 8);
	};
}

void DCP_blockcipher64::encryptCTR(uint8_t *inData, uint8_t *outData, uint32_t size)
{
	uint8_t temp[8];
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	uint8_t *p1 = inData;
	uint8_t *p2 = outData;
	memset(temp, 0, sizeof(temp));
	for (int i = 0; i < size / 8; i++)
	{
		encryptECB(CV, temp);
		incCounter();
		memmove(p2, p1, 8);
		xorBlock(p2, temp, 8);
		p1 += 8;
		p2 += 8;
	};
	if ((size % 8) != 0)
	{
		encryptECB(CV, temp);
		incCounter();
		memmove(p2, p1, size % 8);
		xorBlock(p2, temp, size % 8);
	};
}

void DCP_blockcipher64::decryptCTR(uint8_t *inData, uint8_t *outData, uint32_t size)
{
	uint8_t temp[8];
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	uint8_t *p1 = inData;
	uint8_t *p2 = outData;
	memset(temp, 0, sizeof(temp));
	for (int i = 0; i < size / 8; i++)
	{
		encryptECB(CV, temp);
		incCounter();
		memmove(p2, p1, 8);
		xorBlock(p2, temp, 8);
		p1 += 8;
		p2 += 8;
	};
	if ((size % 8) != 0)
	{
		encryptECB(CV, temp);
		incCounter();
		memmove(p2, p1, size % 8);
		xorBlock(p2, temp, size % 8);
	};
}
