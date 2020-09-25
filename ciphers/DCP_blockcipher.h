/* The base class from which all block ciphers are to be derived, this
   extra class takes care of the different block encryption modes.*/
#pragma once
#include "DCP_cipher.h"

namespace dcpcrypt {

enum DCP_ciphermode { cmCBC, cmCFB8bit, cmCFBblock, cmOFB, cmCTR };
// cmCFB8bit is equal to DCPcrypt v1.xx's CFB mode

class DCP_blockcipher: public DCP_cipher
{
protected:
	DCP_ciphermode fCipherMode; /// The cipher mode the encrypt method uses
	virtual void initKey(uint8_t *key, uint32_t size) = 0;
public:
	DCP_blockcipher() {
		fCipherMode = cmCBC;
	};
	~DCP_blockcipher() {};
	/// Get the block size of the cipher(in bits)
	virtual int getBlockSize() = 0;
	/// Sets the IV to Value and performs a reset
	virtual void setIV(const char *value) = 0;
	/// Returns the current chaining information, not the actual IV
	virtual void getIV(char *value) = 0;
	/// Encrypt size bytes of data and place in outData
	void encrypt(uint8_t *inData, uint8_t *outData, uint32_t size);
	/// Decrypt size bytes of data and place in outData
	void decrypt(uint8_t *inData, uint8_t *outData, uint32_t size);
	/// Encrypt a block of data using the ECB method of encryption
	virtual void encryptECB(uint8_t *inData, uint8_t *outData) = 0;
	/// Decrypt a block of data using the ECB method of decryption
	virtual void decryptECB(uint8_t *inData, uint8_t *outData) = 0;
	/// Encrypt size bytes of data using the CBC method of encryption
	virtual void encryptCBC(uint8_t *inData, uint8_t *outData, uint32_t size) = 0;
	/// Decrypt size bytes of data using the CBC method of decryption
	virtual void decryptCBC(uint8_t *inData, uint8_t *outData, uint32_t size) = 0;
	/// Encrypt size bytes of data using the CFB(8 bit) method of encryption
	virtual void encryptCFB8bit(uint8_t *inData, uint8_t *outData, uint32_t size) = 0;
	/// Decrypt size bytes of data using the CFB(8 bit) method of decryption
	virtual void decryptCFB8bit(uint8_t *inData, uint8_t *outData, uint32_t size) = 0;
	/// Encrypt size bytes of data using the CFB(block) method of encryption
	virtual void encryptCFBblock(uint8_t *inData, uint8_t *outData, uint32_t size) = 0;
	/// Decrypt size bytes of data using the CFB(block) method of decryption
	virtual void decryptCFBblock(uint8_t *inData, uint8_t *outData, uint32_t size) = 0;
	// Encrypt size bytes of data using the OFB method of encryption
	virtual void encryptOFB(uint8_t *inData, uint8_t *outData, uint32_t size) = 0;
	/// Decrypt size bytes of data using the OFB method of decryption
	virtual void decryptOFB(uint8_t *inData, uint8_t *outData, uint32_t size) = 0;
	/// Encrypt size bytes of data using the CTR method of encryption
	virtual void encryptCTR(uint8_t *inData, uint8_t *outData, uint32_t size) = 0;
	/// Decrypt size bytes of data using the CTR method of decryption
	virtual void decryptCTR(uint8_t *inData, uint8_t *outData, uint32_t size) = 0;
};

}