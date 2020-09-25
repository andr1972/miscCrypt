#pragma once
#include "DCP_blockcipher.h"

namespace dcpcrypt {

class DCP_blockcipher128 : public DCP_blockcipher
{
private:
	uint8_t IV[16], CV[16];
	void incCounter();
public:
	DCP_blockcipher128();
	~DCP_blockcipher128();
	int getBlockSize() { return 128; };
	void reset();
	/// Reset any stored chaining information
	void burn();
	/// Clear all stored key information and chaining information
	void setIV(const char *value);
	/// Sets the IV to value and performs a reset
	void getIV(char *value);
	/// Returns the current chaining information, not the actual IV
	void init(uint8_t *Key, uint32_t size, const char *initVector);
	/// Do key setup based on the data in Key, size is in bits

	void encryptCBC(uint8_t *inData, uint8_t *outData, uint32_t size);
	/// Encrypt size bytes of data using the CBC method of encryption
	void decryptCBC(uint8_t *inData, uint8_t *outData, uint32_t size);
	/// Decrypt size bytes of data using the CBC method of decryption
	void encryptCFB8bit(uint8_t *inData, uint8_t *outData, uint32_t size);
	/// Encrypt size bytes of data using the CFB(8 bit) method of encryption
	void decryptCFB8bit(uint8_t *inData, uint8_t *outData, uint32_t size);
	/// Decrypt size bytes of data using the CFB(8 bit) method of decryption
	void encryptCFBblock(uint8_t *inData, uint8_t *outData, uint32_t size);
	/// Encrypt size bytes of data using the CFB(block) method of encryption
	void decryptCFBblock(uint8_t *inData, uint8_t *outData, uint32_t size);
	/// Decrypt size bytes of data using the CFB(block) method of decryption
	void encryptOFB(uint8_t *inData, uint8_t *outData, uint32_t size);
	/// Encrypt size bytes of data using the OFB method of encryption
	void decryptOFB(uint8_t *inData, uint8_t *outData, uint32_t size);
	/// Decrypt size bytes of data using the OFB method of decryption
	void encryptCTR(uint8_t *inData, uint8_t *outData, uint32_t size);
	/// Encrypt size bytes of data using the CTR method of encryption
	void decryptCTR(uint8_t *inData, uint8_t *outData, uint32_t size);
	/// Decrypt size bytes of data using the CTR method of decryption
};

}