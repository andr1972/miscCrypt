#include "DCPh_sha3.h"
#include "Util.h"
#include "Exception.h"
#include <assert.h>

using namespace dcpcrypt;

#if defined(_MSC_VER)
#define SHA3_CONST(x) x
#else
#define SHA3_CONST(x) x##L
#endif

/*** Constants. ***/
static const uint8_t rho[24] = \
{ 1, 3, 6, 10, 15, 21,
28, 36, 45, 55, 2, 14,
27, 41, 56, 8, 25, 43,
62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = \
{10, 7, 11, 17, 18, 3,
5, 16, 8, 21, 24, 4,
15, 23, 19, 13, 12, 2,
20, 14, 22, 9, 6, 1};
static const uint64_t RC[24] = \
{1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};


DCPh_sha3::DCPh_sha3(int digestBits):digestBits(digestBits)
{
	if (digestBits != 224 && digestBits!=256 && digestBits!=384 && digestBits != 512)
		throw EDCP_hash("Bad size SHA3");
}


DCPh_sha3::~DCPh_sha3()
{
}

std::string DCPh_sha3::getAlgorithm()
{
	return "sha3-" + std::to_string(digestBits);
}

int DCPh_sha3::getHashSize()
{
	return digestBits;
}

bool DCPh_sha3::selfTest()
{
	bool result = false;
	if (digestBits == 224)
	{
		uint8_t TestOut[224 / 8];
		init();
		updateStr("");
		final(TestOut);
		std::vector<uint8_t> vhash = fromHex("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
		result = memcmp(TestOut, vhash.data(), vhash.size()) == 0;
		init();
		updateStr("abc");
		final(TestOut);
		vhash = fromHex("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
		result = result && memcmp(TestOut, vhash.data(), vhash.size()) == 0;
		init();
		updateStr("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
		final(TestOut);
		vhash = fromHex("8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33");
		result = result && memcmp(TestOut, vhash.data(), vhash.size()) == 0;
	}
	else if (digestBits == 256)
	{
		const uint8_t Test0Out[256 / 8] = { 0xa7,0xff,0xc6,0xf8,0xbf,0x1e,0xd7,0x66,0x51,0xc1,0x47,0x56,0xa0,0x61,0xd6,0x62,
			0xf5,0x80,0xff,0x4d,0xe4,0x3b,0x49,0xfa,0x82,0xd8,0x0a,0x4b,0x80,0xf8,0x43,0x4a };
		const uint8_t Test1Out[256 / 8] = { 0x3a,0x98,0x5d,0xa7,0x4f,0xe2,0x25,0xb2,0x04,0x5c,0x17,0x2d,0x6b,0xd3,0x90,0xbd,
			0x85,0x5f,0x08,0x6e,0x3e,0x9d,0x52,0x5b,0x46,0xbf,0xe2,0x45,0x11,0x43,0x15,0x32 };
		const uint8_t Test2Out[256 / 8] = { 0x41,0xc0,0xdb,0xa2,0xa9,0xd6,0x24,0x08,0x49,0x10,0x03,0x76,0xa8,0x23,0x5e,0x2c,
			0x82,0xe1,0xb9,0x99,0x8a,0x99,0x9e,0x21,0xdb,0x32,0xdd,0x97,0x49,0x6d,0x33,0x76 };
		const uint8_t Test3Out[256 / 8] = { 0xef,0x89,0x6c,0xf5,0x69,0x1c,0xb0,0x82,0xb0,0x24,0xce,0xa9,0xd7,0xb4,0x27,0xbb,
			0xdc,0x0e,0xe5,0x7f,0xd4,0x16,0x16,0x75,0xfa,0x57,0x53,0x65,0xd4,0x03,0x08,0x03 };
		uint8_t TestOut[256 / 8];
		init();
		updateStr("");
		final(TestOut);
		result = memcmp(TestOut, Test0Out, sizeof(Test0Out)) == 0;
		init();
		updateStr("abc");
		final(TestOut);
		result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0 && result;
		init();
		updateStr("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
		final(TestOut);
		result = memcmp(TestOut, Test2Out, sizeof(Test2Out)) == 0 && result;
		init();
		//more than one 64 byte block
		updateStr("300ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789xyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789xyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789xyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789xy*300ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk");
		final(TestOut);
		result = memcmp(TestOut, Test3Out, sizeof(Test3Out)) == 0 && result;
		//the same divided to many updates
		init();
		updateStr("300");
		updateStr("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
		updateStr("abcdefghijklmnopqrstuvwxyz");
		updateStr("0123456789xy");
		updateStr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcd");
		updateStr("efghijklmnopqrstuvwxyz012345");
		updateStr("6789xyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789xyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk");
		updateStr("lmnopqrstuvwxyz0123456789xy*300ABCDEFGHIJKLMNOPQRSTUVWXYZ");
		updateStr("abcdefghijk");
		final(TestOut);
		result = memcmp(TestOut, Test3Out, sizeof(Test3Out)) == 0 && result;
	}
	else if (digestBits == 384)
	{
		uint8_t TestOut[384 / 8];
		init();
		updateStr("");
		final(TestOut);
		std::vector<uint8_t> vhash = fromHex("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
		result = memcmp(TestOut, vhash.data(), vhash.size()) == 0;
		init();
		updateStr("abc");
		final(TestOut);
		vhash = fromHex("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
		result = result && memcmp(TestOut, vhash.data(), vhash.size()) == 0;
		init();
		updateStr("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
		final(TestOut);
		vhash = fromHex("991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22");
		result = result && memcmp(TestOut, vhash.data(), vhash.size()) == 0;
	}
	else if (digestBits == 512)
	{
		uint8_t TestOut[512 / 8];
		init();
		updateStr("");
		final(TestOut);
		std::vector<uint8_t> vhash = fromHex("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
		result = memcmp(TestOut, vhash.data(), vhash.size()) == 0;
		init();
		updateStr("abc");
		final(TestOut);
		vhash = fromHex("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
		result = result && memcmp(TestOut, vhash.data(), vhash.size()) == 0;
		init();
		updateStr("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
		final(TestOut);
		vhash = fromHex("04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e");
		result = result && memcmp(TestOut, vhash.data(), vhash.size()) == 0;
	}
	else result = false;
	return result;
}

void DCPh_sha3::init()
{
	burn();
	outlen = digestBits / 8;
	rate = 200 - (digestBits / 4);
	fInitialized = true;
}

void DCPh_sha3::burn()
{
	memset(sponge, 0, sizeof(sponge));
	memset(tail, 0, sizeof(tail));
	tailIndex = 0;
	fInitialized = false;
}

inline void xorin(uint8_t* dst, const uint8_t* src, size_t len)
{
	for (size_t i = 0; i < len; i++)
		dst[i] ^= src[i];
}

void DCPh_sha3::update(const unsigned char *in, uint32_t inlen)
{
	if (!fInitialized)
		throw EDCP_hash("Hash not initialized");
	if (tailIndex)
	{
		if (tailIndex + inlen >= rate)
		{
			size_t tailLen = rate - tailIndex;
			memcpy(tail + tailIndex, in, tailLen);
			xorin(sponge, tail, rate);
			keccakf(sponge);
			in += tailLen;
			inlen -= tailLen;
		}
		else
		{
			memcpy(tail + tailIndex, in, inlen);
			tailIndex += inlen;
			return;
		}
	}
	// Absorb input.
	while (inlen >= rate) {
		xorin(sponge, in, rate);
		keccakf(sponge);
		in += rate;
		inlen -= rate;
	}
	memcpy(tail, in, inlen);
	tailIndex = inlen;
}


void DCPh_sha3::final(uint8_t * digest)
{
	if (!fInitialized)
		throw EDCP_hash("Hash not initialized");
	// Xor in the DS and pad frame.
	sponge[tailIndex] ^= 0x06;//delim=0x06
	sponge[rate - 1] ^= 0x80;
	// Xor in the last block.
	xorin(sponge, tail, tailIndex);
	// Apply P
	keccakf(sponge);
	memcpy(digest, sponge, outlen);
	burn();
}

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
  v = 0;            \
  REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
void DCPh_sha3::keccakf(void* state)
{
	uint64_t* a = (uint64_t*)state;
	uint64_t b[5] = { 0 };
	uint64_t t = 0;
	uint8_t x, y;

	for (int i = 0; i < 24; i++) {
		// Theta
		FOR5(x, 1,
			b[x] = 0;
		FOR5(y, 5,
			b[x] ^= a[x + y]; ))
			FOR5(x, 1,
				FOR5(y, 5,
					a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1); ))
			// Rho and pi
			t = a[1];
		x = 0;
		REPEAT24(b[0] = a[pi[x]];
		a[pi[x]] = rol(t, rho[x]);
		t = b[0];
		x++; )
			// Chi
			FOR5(y,
				5,
				FOR5(x, 1,
					b[x] = a[y + x];)
				FOR5(x, 1,
					a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
			// Iota
			a[0] ^= RC[i];
	}
}
