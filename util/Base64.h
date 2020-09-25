#pragma once
#include <string>

namespace dcpcrypt {

class Base64
{
	static bool initialized;
	static char base64_table[65];
	static int base64_invtable[256];
public:
	Base64();
	~Base64();
	std::string encode(const unsigned char *src, size_t len);
	const std::string decode(const void* data, const size_t &len);
};

}