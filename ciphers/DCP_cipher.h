/* The base class from which all encryption components will be derived.
   Stream ciphers will be derived directly from this class where as
   Block ciphers will have a further foundation class TDCP_blockcipher. */
#pragma once
#include <string>
#include "../util/DCP_const.h"

namespace dcpcrypt {

class DCP_cipher
{
protected:
	bool fInitialized = false; /// Whether or not the key setup has been done yet
public:
	DCP_cipher() {};
	virtual ~DCP_cipher() {};
	bool getInitialized() { return fInitialized; }
	/// Get the algorithm id
	virtual DCPenum getId() = 0;
	/// Get the algorithm name
	virtual std::string getAlgorithm() = 0;
	// Get the maximum key size(in bits) }
	virtual int getMaxKeySize() =  0;
	/// Tests the implementation with several test vectors
	virtual bool selfTest() = 0;
	/// Clear all stored key information
	virtual void burn() = 0;
	/// Reset any stored chaining information
	virtual void reset() = 0;
	/// Initialize the hash algorithm
	virtual void init(uint8_t *key, uint32_t size, const char *initVector);
	/// Encrypt size bytes of data and place in outData
	virtual void encrypt(uint8_t *inData, uint8_t *outData, uint32_t size) = 0;
	/// Decrypt size bytes of data and place in outData
	virtual void decrypt(uint8_t *inData, uint8_t *outData, uint32_t size) = 0;
};

}