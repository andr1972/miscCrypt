#include "DCP_const.h"
#include "DCPc_rijndael.h"
#include "Exception.h"
#include "Util.h"
#include <vector>

#include "DCPc_rijndael_tabs.h"

using namespace dcpcrypt;

DCPc_rijndael::DCPc_rijndael()
{
}


DCPc_rijndael::~DCPc_rijndael()
{
}

int DCPc_rijndael::getMaxKeySize()
{
	return 256;
}

DCPenum DCPc_rijndael::getId()
{
	return DCPenum::c_rijndael;
}

std::string DCPc_rijndael::getAlgorithm()
{
	return "rijndael";
}

bool DCPc_rijndael::selfTest()
{
	uint8_t Key1[16] =
	{ 0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12 };
	uint8_t inData1[16] =
	{ 0x50, 0x68, 0x12, 0xA4, 0x5F, 0x08, 0xC8, 0x89, 0xB9, 0x7F, 0x59, 0x80, 0x03, 0x8B, 0x83, 0x59 };
	uint8_t OutData1[16] =
	{ 0xD8, 0xF5, 0x32, 0x53, 0x82, 0x89, 0xEF, 0x7D, 0x06, 0xB5, 0x06, 0xA4, 0xFD, 0x5B, 0xE9, 0xC9 };
	uint8_t Key2[24] =
	{ 0xA0, 0xA1, 0xA2, 0xA3, 0xA5, 0xA6, 0xA7, 0xA8, 0xAA, 0xAB, 0xAC, 0xAD, 0xAF, 0xB0, 0xB1, 0xB2,
		0xB4, 0xB5, 0xB6, 0xB7, 0xB9, 0xBA, 0xBB, 0xBC };
	uint8_t inData2[16] =
	{ 0x4F, 0x1C, 0x76, 0x9D, 0x1E, 0x5B, 0x05, 0x52, 0xC7, 0xEC, 0xA8, 0x4D, 0xEA, 0x26, 0xA5, 0x49 };
	uint8_t OutData2[16] =
	{ 0xF3, 0x84, 0x72, 0x10, 0xD5, 0x39, 0x1E, 0x23, 0x60, 0x60, 0x8E, 0x5A, 0xCB, 0x56, 0x05, 0x81 };
	uint8_t Key3[32] =
	{ 0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12,
		0x14, 0x15, 0x16, 0x17, 0x19, 0x1A, 0x1B, 0x1C, 0x1E, 0x1F, 0x20, 0x21, 0x23, 0x24, 0x25, 0x26 };
	uint8_t inData3[16] =
	{ 0x5E, 0x25, 0xCA, 0x78, 0xF0, 0xDE, 0x55, 0x80, 0x25, 0x24, 0xD3, 0x8D, 0xA3, 0xFE, 0x44, 0x56 };
	uint8_t OutData3[16] =
	{ 0xE8, 0xB7, 0x2B, 0x4E, 0x8B, 0xE2, 0x43, 0x43, 0x8C, 0x9F, 0xFF, 0x1F, 0x0E, 0x20, 0x58, 0x72 };

	uint8_t Block[16];

	memset(Block, 0, sizeof(Block));
	init(Key1, sizeof(Key1) * 8, nullptr);
	encryptECB(inData1, Block);
	bool result = memcmp(Block, OutData1, 16) == 0;
	decryptECB(Block, Block);
	burn();
	result = result && memcmp(Block, inData1, 16) == 0;
	init(Key2, sizeof(Key2) * 8, nullptr);
	encryptECB(inData2, Block);
	result = result && memcmp(Block, OutData2, 16) == 0;
	decryptECB(Block, Block);
	burn();
	result = result && memcmp(Block, inData2, 16) == 0;
	init(Key3, sizeof(Key3) * 8, nullptr);
	encryptECB(inData3, Block);
	result = result && memcmp(Block, OutData3, 16) == 0;
	decryptECB(Block, Block);
	burn();
	result = result && memcmp(Block, inData3, 16) == 0;

	//https://www.hanewin.net/encrypt/aes/aes-test.htm
	std::vector<uint8_t> vkey = fromHex("E8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA");
	std::vector<uint8_t> vplain = fromHex("014BAF2278A69D331D5180103643E99A");
	std::vector<uint8_t> vcipher = fromHex("6743C3D1519AB4F2CD9A78AB09A511BD");
	init(vkey.data(), vkey.size() * 8, nullptr);
	encryptECB(vplain.data(), Block);
	result = result && memcmp(Block, vcipher.data(), 16) == 0;

	vkey = fromHex("04050607090A0B0C0E0F10111314151618191A1B1D1E1F20");
	vplain = fromHex("76777475F1F2F3F4F8F9E6E777707172");
	vcipher = fromHex("5d1ef20dced6bcbc12131ac7c54788aa");
	init(vkey.data(), vkey.size() * 8, nullptr);
	encryptECB(vplain.data(), Block);
	result = result && memcmp(Block, vcipher.data(), 16) == 0;

	vkey = fromHex("08090A0B0D0E0F10121314151718191A1C1D1E1F21222324262728292B2C2D2E");
	vplain = fromHex("069A007FC76A459F98BAF917FEDF9521");
	vcipher = fromHex("080e9517eb1677719acf728086040ae3");
	init(vkey.data(), vkey.size() * 8, nullptr);
	encryptECB(vplain.data(), Block);
	result = result && memcmp(Block, vcipher.data(), 16) == 0;

	return result;
}

void DCPc_rijndael::burn()
{
    numrounds = 0;
	memset(rk, 0, sizeof(rk));
	memset(drk, 0, sizeof(drk));
	DCP_blockcipher128::burn();
}

void DCPc_rijndael::encryptECB(uint8_t * inData, uint8_t * outData)
{
	uint8_t tempb[4][4], a[4][4];
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	*((uint32_t*)(&a[0][ 0]) ) = *((uint32_t*)(inData));
	*((uint32_t*)(&a[1][ 0]) ) = *((uint32_t*)(inData + 4) ) ;
	*((uint32_t*)(&a[2][ 0]) ) = *((uint32_t*)(inData + 8) ) ;
	*((uint32_t*)(&a[3][ 0]) ) = *((uint32_t*)(inData + 12) ) ;
	for (uint32_t r = 0; r <= numrounds - 2; r++)
	{
	*((uint32_t*)(&tempb[0]) ) = *((uint32_t*)(&a[0]) ) ^ rk[r][ 0];
	*((uint32_t*)(&tempb[1]) ) = *((uint32_t*)(&a[1]) ) ^ rk[r][ 1];
	*((uint32_t*)(&tempb[2]) ) = *((uint32_t*)(&a[2]) ) ^ rk[r][ 2];
	*((uint32_t*)(&tempb[3]) ) = *((uint32_t*)(&a[3]) ) ^ rk[r][ 3];
	*((uint32_t*)(&a[0]) ) = *((uint32_t*)(&T1[tempb[0][ 0]]) ) ^
		*((uint32_t*)(&T2[tempb[1][ 1]]) ) ^
		*((uint32_t*)(&T3[tempb[2][ 2]]) ) ^
		*((uint32_t*)(&T4[tempb[3][ 3]]) ) ;
	*((uint32_t*)(&a[1]) ) = *((uint32_t*)(&T1[tempb[1][ 0]]) ) ^
		*((uint32_t*)(&T2[tempb[2][ 1]]) ) ^
		*((uint32_t*)(&T3[tempb[3][ 2]]) ) ^
		*((uint32_t*)(&T4[tempb[0][ 3]]) ) ;
	*((uint32_t*)(&a[2]) ) = *((uint32_t*)(&T1[tempb[2][ 0]]) ) ^
		*((uint32_t*)(&T2[tempb[3][ 1]]) ) ^
		*((uint32_t*)(&T3[tempb[0][ 2]]) ) ^
		*((uint32_t*)(&T4[tempb[1][ 3]]) ) ;
	*((uint32_t*)(&a[3]) ) = *((uint32_t*)(&T1[tempb[3][ 0]]) ) ^
		*((uint32_t*)(&T2[tempb[0][ 1]]) ) ^
		*((uint32_t*)(&T3[tempb[1][ 2]]) ) ^
		*((uint32_t*)(&T4[tempb[2][ 3]]) ) ;
	}
	*((uint32_t*)(&tempb[0]) ) = *((uint32_t*)(&a[0]) ) ^ rk[numrounds - 1][ 0];
	*((uint32_t*)(&tempb[1]) ) = *((uint32_t*)(&a[1]) ) ^ rk[numrounds - 1][ 1];
	*((uint32_t*)(&tempb[2]) ) = *((uint32_t*)(&a[2]) ) ^ rk[numrounds - 1][ 2];
	*((uint32_t*)(&tempb[3]) ) = *((uint32_t*)(&a[3]) ) ^ rk[numrounds - 1][ 3];
	a[0][ 0]= T1[tempb[0][ 0]][ 1];
	a[0][ 1]= T1[tempb[1][ 1]][ 1];
	a[0][ 2]= T1[tempb[2][ 2]][ 1];
	a[0][ 3]= T1[tempb[3][ 3]][ 1];
	a[1][ 0]= T1[tempb[1][ 0]][ 1];
	a[1][ 1]= T1[tempb[2][ 1]][ 1];
	a[1][ 2]= T1[tempb[3][ 2]][ 1];
	a[1][ 3]= T1[tempb[0][ 3]][ 1];
	a[2][ 0]= T1[tempb[2][ 0]][ 1];
	a[2][ 1]= T1[tempb[3][ 1]][ 1];
	a[2][ 2]= T1[tempb[0][ 2]][ 1];
	a[2][ 3]= T1[tempb[1][ 3]][ 1];
	a[3][ 0]= T1[tempb[3][ 0]][ 1];
	a[3][ 1]= T1[tempb[0][ 1]][ 1];
	a[3][ 2]= T1[tempb[1][ 2]][ 1];
	a[3][ 3]= T1[tempb[2][ 3]][ 1];
	*((uint32_t*)(&a[0]) ) = *((uint32_t*)(&a[0]) ) ^ rk[numrounds][ 0];
	*((uint32_t*)(&a[1]) ) = *((uint32_t*)(&a[1]) ) ^ rk[numrounds][ 1];
	*((uint32_t*)(&a[2]) ) = *((uint32_t*)(&a[2]) ) ^ rk[numrounds][ 2];
	*((uint32_t*)(&a[3]) ) = *((uint32_t*)(&a[3]) ) ^ rk[numrounds][ 3];

	*((uint32_t*)(outData))= *((uint32_t*)(&a[0][ 0]) ) ;
	*((uint32_t*)(outData + 4) ) = *((uint32_t*)(&a[1][ 0]) ) ;
	*((uint32_t*)(outData + 8) ) = *((uint32_t*)(&a[2][ 0]) ) ;
	*((uint32_t*)(outData + 12) ) = *((uint32_t*)(&a[3][ 0]) ) ;

}

void DCPc_rijndael::decryptECB(uint8_t * inData, uint8_t * outData)
{
	uint8_t tempb[4][4], a[4][4];
	if (!fInitialized)
		throw EDCP_blockcipher("Cipher not initialized");
	*((uint32_t*)(&a[0][ 0]) )  = *((uint32_t*)(inData));
	*((uint32_t*)(&a[1][ 0]) )  = *((uint32_t*)(inData + 4) ) ;
	*((uint32_t*)(&a[2][ 0]) )  = *((uint32_t*)(inData + 8) ) ;
	*((uint32_t*)(&a[3][ 0]) )  = *((uint32_t*)(inData + 12) ) ;
	for (uint32_t r = numrounds; r >= 2; r--)
	{
		*((uint32_t*)(&tempb[0])) = *((uint32_t*)(&a[0])) ^ drk[r][0];
		*((uint32_t*)(&tempb[1])) = *((uint32_t*)(&a[1])) ^ drk[r][1];
		*((uint32_t*)(&tempb[2])) = *((uint32_t*)(&a[2])) ^ drk[r][2];
		*((uint32_t*)(&tempb[3])) = *((uint32_t*)(&a[3])) ^ drk[r][3];
		*((uint32_t*)(a[0])) = *((uint32_t*)(&T5[tempb[0][0]])) ^
			*((uint32_t*)(&T6[tempb[3][1]])) ^
			*((uint32_t*)(&T7[tempb[2][2]])) ^
			*((uint32_t*)(&T8[tempb[1][3]]));
		*((uint32_t*)(a[1])) = *((uint32_t*)(&T5[tempb[1][0]])) ^
			*((uint32_t*)(&T6[tempb[0][1]])) ^
			*((uint32_t*)(&T7[tempb[3][2]])) ^
			*((uint32_t*)(&T8[tempb[2][3]]));
		*((uint32_t*)(a[2])) = *((uint32_t*)(&T5[tempb[2][0]])) ^
			*((uint32_t*)(&T6[tempb[1][1]])) ^
			*((uint32_t*)(&T7[tempb[0][2]])) ^
			*((uint32_t*)(&T8[tempb[3][3]]));
		*((uint32_t*)(a[3])) = *((uint32_t*)(&T5[tempb[3][0]])) ^
			*((uint32_t*)(&T6[tempb[2][1]])) ^
			*((uint32_t*)(&T7[tempb[1][2]])) ^
			*((uint32_t*)(&T8[tempb[0][3]]));
	}
	*((uint32_t*)(&tempb[0]) )  = *((uint32_t*)(&a[0]) ) ^ drk[1][ 0];
	*((uint32_t*)(&tempb[1]) )  = *((uint32_t*)(&a[1]) ) ^ drk[1][ 1];
	*((uint32_t*)(&tempb[2]) )  = *((uint32_t*)(&a[2]) ) ^ drk[1][ 2];
	*((uint32_t*)(&tempb[3]) )  = *((uint32_t*)(&a[3]) ) ^ drk[1][ 3];
	a[0][ 0] = S5[tempb[0][ 0]];
	a[0][ 1] = S5[tempb[3][ 1]];
	a[0][ 2] = S5[tempb[2][ 2]];
	a[0][ 3] = S5[tempb[1][ 3]];
	a[1][ 0] = S5[tempb[1][ 0]];
	a[1][ 1] = S5[tempb[0][ 1]];
	a[1][ 2] = S5[tempb[3][ 2]];
	a[1][ 3] = S5[tempb[2][ 3]];
	a[2][ 0] = S5[tempb[2][ 0]];
	a[2][ 1] = S5[tempb[1][ 1]];
	a[2][ 2] = S5[tempb[0][ 2]];
	a[2][ 3] = S5[tempb[3][ 3]];
	a[3][ 0] = S5[tempb[3][ 0]];
	a[3][ 1] = S5[tempb[2][ 1]];
	a[3][ 2] = S5[tempb[1][ 2]];
	a[3][ 3] = S5[tempb[0][ 3]];
	*((uint32_t*)(&a[0]) )  = *((uint32_t*)(&a[0]) ) ^ drk[0][ 0];
	*((uint32_t*)(&a[1]) )  = *((uint32_t*)(&a[1]) ) ^ drk[0][ 1];
	*((uint32_t*)(&a[2]) )  = *((uint32_t*)(&a[2]) ) ^ drk[0][ 2];
	*((uint32_t*)(&a[3]) )  = *((uint32_t*)(&a[3]) ) ^ drk[0][ 3];
	*((uint32_t*)(outData)) = *((uint32_t*)(&a[0][ 0]) ) ;
	*((uint32_t*)(outData + 4) )  = *((uint32_t*)(&a[1][ 0]) ) ;
	*((uint32_t*)(outData + 8) )  = *((uint32_t*)(&a[2][ 0]) ) ;
	*((uint32_t*)(outData + 12) )  = *((uint32_t*)(&a[3][ 0]) ) ;
}

void invMixColumn(uint8_t *a, uint8_t BC)
{
	for (int j = 0; j < BC; j++)
		*((uint32_t*)(&(a[j * 4]))) = *((uint32_t*)(&U1[a[j * 4 + 0]])) ^
		*((uint32_t*)(&U2[a[j * 4 + 1]])) ^
		*((uint32_t*)(&U3[a[j * 4 + 2]])) ^
		*((uint32_t*)(&U4[a[j * 4 + 3]]));
}


void DCPc_rijndael::initKey(uint8_t *key, uint32_t size)
{
	uint32_t KC, rounds, j, r, t, rconpointer;
	uint8_t tk[MAXKC][4];

	size = size / 8;

	memset(tk, 0, sizeof(tk));
	memmove(tk, key, size);
	if (size <= 16)
	{
		KC = 4;
		rounds = 10;
	}
	else if (size <= 24)
	{
		KC = 6;
		rounds = 12;
	}
	else
	{
		KC = 8;
		rounds = 14;
	}
	numrounds = rounds;
	r = 0;
	t = 0;
	j = 0;
	while (j< KC && r< (rounds + 1))
	{
		while (j< KC && t< BC)
		{
			rk[r][t] = *((uint32_t*)(tk + j));
			j++;
			t++;
		}
		if (t == BC)
		{
			t = 0;
			r++;
		}
	}
	rconpointer = 0;
	while (r< (rounds + 1))
	{
		tk[0][0] = tk[0][0] ^ S[tk[KC - 1][1]];
		tk[0][1] = tk[0][1] ^ S[tk[KC - 1][2]];
		tk[0][2] = tk[0][2] ^ S[tk[KC - 1][3]];
		tk[0][3] = tk[0][3] ^ S[tk[KC - 1][0]];
		tk[0][0] = tk[0][0] ^ rcon[rconpointer];
		rconpointer++;
		if (KC != 8)
		{
			for (int j = 1; j< KC; j++)
				*((uint32_t*)(tk + j)) = *((uint32_t*)(tk + j)) ^ *((uint32_t*)(tk + j - 1));
		}
		else
		{
			for (int j = 1; j< KC / 2; j++)
				*((uint32_t*)(tk + j)) = *((uint32_t*)(tk + j)) ^ *((uint32_t*)(tk + j - 1));
			tk[KC / 2][0] = tk[KC / 2][0] ^ S[tk[KC / 2 - 1][0]];
			tk[KC / 2][1] = tk[KC / 2][1] ^ S[tk[KC / 2 - 1][1]];
			tk[KC / 2][2] = tk[KC / 2][2] ^ S[tk[KC / 2 - 1][2]];
			tk[KC / 2][3] = tk[KC / 2][3] ^ S[tk[KC / 2 - 1][3]];
			for (int j = KC / 2 + 1; j < KC; j++)
				*((uint32_t*)(tk + j)) = *((uint32_t*)(tk + j)) ^ *((uint32_t*)(tk + j - 1));
		}
		j = 0;
		while (j< KC && r< (rounds + 1))
		{
			while (j< KC && t< BC)
			{
				rk[r][t] = *((uint32_t*)(tk + j));
				j++;
				t++;
			}
			if (t == BC)
			{
				r++;
				t = 0;
			}
		}
	}
	memmove(drk, rk, sizeof(rk));
	for (int r = 1; r<numrounds; r++)
		invMixColumn((uint8_t *)(drk + r), BC);
}
