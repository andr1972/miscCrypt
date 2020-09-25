#pragma once

namespace dcpcrypt {

enum class DCPenum {
	c_rc2 = 1,
	h_sha1_160 = 2,
	c_rc5 = 3,
	c_rc6 = 4,
	c_blowfish = 5,
	c_twofish = 6,
	c_cast128 = 7,
	c_gost = 8,
	c_rijndael = 9,
	h_ripemd160 = 10,
	c_misty1 = 11,
	c_idea = 12,
	c_mars = 13,
	h_havalPas = 14,
	c_cast256 = 15,
	h_md5 = 16,
	h_md4 = 17,
	h_tiger = 18,
	c_rc4 = 19,
	c_ice = 20,
	c_thinice = 21,
	c_ice2 = 22,
	c_des = 23,
	c_3des = 24,
	c_tea = 25,
	c_serpent = 26,
	h_ripemd128 = 27,
	h_sha2_256 = 28,
	h_sha2_384 = 29,
	h_sha2_512 = 30,
	h_haval = 31,
	h_sha3 = 32,
	h_blake2b = 33,
	h_blake2s = 34,
	h_blake2bSSE = 35,
	h_blake2sSSE = 36
};

}