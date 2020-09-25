#include "DCP_cipher.h"
#include "Exception.h"

using namespace dcpcrypt;

void DCP_cipher::init(uint8_t *key, uint32_t size, const char *initVector)
{
	if (fInitialized)
		burn();
	if (size <= 0 || (size & 3) != 0 || size > getMaxKeySize())
		throw EDCP_cipher("Invalid key size");
	else
		fInitialized = true;

}