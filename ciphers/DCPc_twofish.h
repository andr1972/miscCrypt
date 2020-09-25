#pragma once
#include "DCP_blockcipher128.h"

namespace dcpcrypt {

const int INPUTWHITEN = 0;
const int OUTPUTWHITEN = 4;
const int NUMROUNDS = 16;
const int ROUNDSUBKEYS = OUTPUTWHITEN + 4;
const int TOTALSUBKEYS = ROUNDSUBKEYS + NUMROUNDS * 2;
const int RS_GF_FDBK = 0x14d;
const int MDS_GF_FDBK = 0x169;
const int SK_STEP = 0x02020202;
const int SK_BUMP = 0x01010101;
const int SK_ROTL = 9;

class DCPc_twofish : public DCP_blockcipher128
{
protected:
	static bool MDSdone;
	static uint32_t MDS[4][256];
	static void preCompMDS();
	static uint32_t f32(uint32_t x, uint32_t *K32, uint32_t Len);
	uint32_t subKeys[TOTALSUBKEYS];
	uint32_t sBox[4][256];
	void initKey(uint8_t *key, uint32_t size);
public:
	DCPc_twofish();
	~DCPc_twofish();
	int getMaxKeySize();
	DCPenum getId();
	std::string getAlgorithm();
	void burn();
	void encryptECB(uint8_t *inData, uint8_t *outData);
	void decryptECB(uint8_t *inData, uint8_t *outData);
	bool selfTest();
};

}