/*
* Base on libkeccak-tiny
* https://github.com/coruus/keccak-tiny
* Implementor: David Leon Gil
* License: CC0, attribution kindly requested. Blame taken too,
* but not liability.
*
* Added multiple update one hash
*/
#pragma once
#include "DCP_hash.h"
#include <stdint.h>

namespace dcpcrypt {

class DCPh_sha3 : public DCP_hash
{
protected:
	int digestBits;
	size_t rate;
	size_t outlen;
	uint8_t sponge[1600 / 8];
	uint8_t tail[200 - (224 / 4)];//max rate size
	size_t tailIndex;
	static void keccakf(void* state);
public:
	DCPh_sha3(int digestBits);
	~DCPh_sha3();
	virtual DCPenum getId() { return DCPenum::h_sha3; };
	/// Get the algorithm name
	std::string getAlgorithm();
	/// Get the size of the digest produced - in bits
	int getHashSize();
	/// Tests the implementation with several test vectors
	bool selfTest();
	/// Initialize the hash algorithm
	void init();
	/// Create the final digest and clear the stored information.
	/// The size of the Digest var must be at least equal to the hash size
	void final(uint8_t *digest);
	/// Clear any stored information with out creating the final digest
	void burn();
	/// Update the hash buffer with Size bytes of data from Buffer
	void update(const unsigned char *buffer, uint32_t size);
};

}