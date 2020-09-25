#include "Base64.h"
#include <string.h>
#include <string>
using namespace dcpcrypt;

bool Base64::initialized = false;
char Base64::base64_table[65];
int Base64::base64_invtable[256];

Base64::Base64()
{
	if (!initialized)
	{
		strcpy(base64_table, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
		memset(base64_invtable, 0, sizeof(base64_invtable));
		for (int i = 0; i < 64; i++)
		{
			base64_invtable[base64_table[i]] = i;
		}
		initialized = true;
	}
}


Base64::~Base64()
{
}

//https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
/*
* Base64 encoding (RFC1341)
* Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
*
* This software may be distributed under the terms of the BSD license.
* See README for more details.
*/
/**
* base64_encode - Base64 encode
* @src: Data to be encoded
* @len: Length of the data to be encoded
* @out_len: Pointer to output length variable, or %NULL if not used
* Returns: Allocated buffer of out_len bytes of encoded data,
* or empty string on failure
*/
std::string Base64::encode(const unsigned char *src, size_t len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;

	size_t olen;

	olen = 4 * ((len + 2) / 3); /* 3-byte blocks to 4-byte */

	if (olen < len)
		return std::string(); /* integer overflow */

	std::string outStr;
	outStr.resize(olen);
	out = (unsigned char*)&outStr[0];

	end = src + len;
	in = src;
	pos = out;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		}
		else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
				(in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
	}
	return outStr;
}

//polfosol
//https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c/13935718
const std::string Base64::decode(const void* data, const size_t &len)
{
	if (len == 0) return "";
	unsigned char *p = (unsigned char*)data;
	size_t j = 0,
		pad1 = len % 4 || p[len - 1] == '=',
		pad2 = pad1 && (len % 4 > 2 || p[len - 2] != '=');
	const size_t last = (len - pad1) / 4 << 2;
	std::string result(last / 4 * 3 + pad1 + pad2, '\0');
	unsigned char *str = (unsigned char*)&result[0];

	for (size_t i = 0; i < last; i += 4)
	{
		int n = base64_invtable[p[i]] << 18 | base64_invtable[p[i + 1]] << 12 | base64_invtable[p[i + 2]] << 6 | base64_invtable[p[i + 3]];
		str[j++] = n >> 16;
		str[j++] = n >> 8 & 0xFF;
		str[j++] = n & 0xFF;
	}
	if (pad1)
	{
		int n = base64_invtable[p[last]] << 18 | base64_invtable[p[last + 1]] << 12;
		str[j++] = n >> 16;
		if (pad2)
		{
			n |= base64_invtable[p[last + 2]] << 6;
			str[j++] = n >> 8 & 0xFF;
		}
	}
	return result;
}
