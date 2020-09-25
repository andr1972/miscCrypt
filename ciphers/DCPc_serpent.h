/*A binary compatible implementation of Serpent ****************************
*Based on C source written by Brian Gladman(gladman@seven77.demon.co.uk) ***
*Thanks to Bruce Christensen for the initial Delphi translation ************
****************************************************************************
*Copyright(c) 2002 David Barton

 this is optimized Serpent version, for explained version see
 https://github.com/Chronic-Dev/libgcrypt/blob/master/cipher/serpent.c
*/

#pragma once
#include "DCP_blockcipher128.h"

namespace dcpcrypt {

class DCPc_serpent : public DCP_blockcipher128
{
protected:
	uint32_t l_key[132];
	void initKey(uint8_t *key, uint32_t size);
public:
	DCPc_serpent();
	~DCPc_serpent();
	int getMaxKeySize();
	DCPenum getId();
	std::string getAlgorithm();
	void burn();
	void encryptECB(uint8_t *inData, uint8_t *outData);
	void decryptECB(uint8_t *inData, uint8_t *outData);
	bool selfTest();
};

}