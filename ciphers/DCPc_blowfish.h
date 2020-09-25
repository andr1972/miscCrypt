#pragma once
#include "DCP_blockcipher64.h"

namespace dcpcrypt {

class DCPc_blowfish : public DCP_blockcipher64
{
protected:
	uint32_t SBox[4][256];
	uint32_t PBox[18];
	void initKey(uint8_t *key, uint32_t size);
public:
	DCPc_blowfish();
	~DCPc_blowfish();
	int getMaxKeySize();
	DCPenum getId();
	std::string getAlgorithm();
	void burn();
	void encryptECB(uint8_t *inData, uint8_t *outData);
	void decryptECB(uint8_t *inData, uint8_t *outData);
	bool selfTest();
};
}