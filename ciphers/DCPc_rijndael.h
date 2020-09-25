#pragma once
#include "DCP_blockcipher128.h"

namespace dcpcrypt {
const int BC = 4;
const int MAXROUNDS = 14;

class DCPc_rijndael : public DCP_blockcipher128
{
protected:
	int numrounds;
	uint32_t rk[MAXROUNDS + 1][8], drk[MAXROUNDS + 1][8];
	void initKey(uint8_t *key, uint32_t size);
public:
	DCPc_rijndael();
	~DCPc_rijndael();
	int getMaxKeySize();
	DCPenum getId();
	std::string getAlgorithm();
	void burn();
	void encryptECB(uint8_t *inData, uint8_t *outData);
	void decryptECB(uint8_t *inData, uint8_t *outData);
	bool selfTest();
};

}