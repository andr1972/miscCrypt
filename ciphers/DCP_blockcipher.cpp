#include "DCP_blockcipher.h"
#include "Exception.h"

using namespace dcpcrypt;

void DCP_blockcipher::encrypt(uint8_t *inData, uint8_t *outData, uint32_t size)
{
	switch (fCipherMode)
	{
	case cmCBC:
		encryptCBC(inData, outData, size);
		break;
	case cmCFB8bit:
		encryptCFB8bit(inData, outData, size);
		break;
	case cmCFBblock:
		encryptCFBblock(inData, outData, size);
		break;
	case cmOFB:
		encryptOFB(inData, outData, size);
		break;
	case cmCTR:
		encryptCTR(inData, outData, size);
		break;
	default: throw EDCP_cipher("Bad cipher mode");
	}
}

void DCP_blockcipher::decrypt(uint8_t *inData, uint8_t *outData, uint32_t size)
{
	switch (fCipherMode)
	{
	case cmCBC:
		decryptCBC(inData, outData, size);
		break;
	case cmCFB8bit:
		decryptCFB8bit(inData, outData, size);
		break;
	case cmCFBblock:
		decryptCFBblock(inData, outData, size);
		break;
	case cmOFB:
		decryptOFB(inData, outData, size);
		break;
	case cmCTR:
		decryptCTR(inData, outData, size);
		break;
	default: throw EDCP_cipher("Bad cipher mode");
	}
}
