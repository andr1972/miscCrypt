#pragma once
#include "../util/DCP_const.h"
#include <string>

#if defined(_MSC_VER)
#define ALIGN(x) __declspec(align(x))
#else
#define ALIGN(x) __attribute__((aligned(x)))
#endif

namespace dcpcrypt {
class DCP_hash
{
protected:
	/// Whether or not the algorithm has been initialized }
	bool fInitialized = false;
public:
	DCP_hash() {};
	virtual ~DCP_hash() {};
	bool getInitialized() { return fInitialized; }
	/// Get the algorithm id
	virtual DCPenum getId() = 0;
	/// Get the algorithm name
	virtual std::string getAlgorithm() = 0;
	/// Get the size of the digest produced - in bits
	virtual int getHashSize() = 0;
	/// Tests the implementation with several test vectors
	virtual bool selfTest() = 0;
	/// Initialize the hash algorithm
	virtual void init() = 0;
	/// Create the final digest and clear the stored information.
	/// The size of the Digest var must be at least equal to the hash size
	virtual void final(unsigned char *digest) = 0;
	/// Clear any stored information with out creating the final digest
	virtual void burn() = 0;
	/// Update the hash buffer with Size bytes of data from Buffer
	virtual void update(const unsigned char *buffer, uint32_t size) = 0;
	/// Update the hash buffer with the string
	virtual void updateStr(const std::string &str) {
		update((const unsigned char *)str.c_str(), (uint32_t)str.length());
	}
};

}