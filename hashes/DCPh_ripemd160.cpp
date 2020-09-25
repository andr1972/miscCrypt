#include "DCPh_ripemd160.h"
#include "Util.h"
#include "Exception.h"

using namespace dcpcrypt;

DCPh_ripemd160::DCPh_ripemd160()
{
}


DCPh_ripemd160::~DCPh_ripemd160()
{
}

std::string DCPh_ripemd160::getAlgorithm()
{
	return "ripemd-160";
}

int DCPh_ripemd160::getHashSize()
{
	return 160;
}

bool DCPh_ripemd160::selfTest()
{
	const uint8_t Test1Out[20] = { 0x0B,0xDC,0x9D,0x2D,0x25,0x6B,0x3E,0xE9,0xDA,0xAE,0x34,0x7B,0xE6,0xF4,0xDC,0x83,0x5A,0x46,0x7F,0xFE };
	const uint8_t Test2Out[20] = { 0xF7,0x1C,0x27,0x10,0x9C,0x69,0x2C,0x1B,0x56,0xBB,0xDC,0xEB,0x5B,0x9D,0x28,0x65,0xB3,0x70,0x8D,0xBC };
	uint8_t TestOut[20];
	init();
	updateStr("a");
	final(TestOut);
	bool result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
	init();
	updateStr("abcdefghijklmnopqrstuvwxyz");
	final(TestOut);
	result = memcmp(TestOut, Test2Out, sizeof(Test2Out)) == 0 && result;
	return result;
}

void DCPh_ripemd160::init()
{
	burn();
	CurrentHash[0] = 0x67452301;
	CurrentHash[1] = 0xefcdab89;
	CurrentHash[2] = 0x98badcfe;
	CurrentHash[3] = 0x10325476;
	CurrentHash[4] = 0xc3d2e1f0;
	fInitialized = true;
}

void DCPh_ripemd160::burn()
{
	lenHi = 0; lenLo = 0;
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
	memset(CurrentHash, 0, sizeof(CurrentHash));
	fInitialized = false;
}

void DCPh_ripemd160::update(const unsigned char *buffer, uint32_t size)
{
	if (!fInitialized)
		throw EDCP_hash("Hash not initialized");

	lenHi += size >> 29;
	lenLo += size * 8;
	if (lenLo < size * 8)
		lenHi++;

	const unsigned char *PBuf = buffer;
	while (size > 0)
	{
		if (sizeof(HashBuffer) - index <= uint32_t(size))
		{
			memmove(HashBuffer + index, PBuf, sizeof(HashBuffer) - index);
			size -= sizeof(HashBuffer) - index;
			PBuf += sizeof(HashBuffer) - index;
			compress();
		}
		else
		{
			memmove(HashBuffer + index, PBuf, size);
			index += size;
			size = 0;
		}
	}
}


void DCPh_ripemd160::final(uint8_t * digest)
{
	if (!fInitialized)
		throw EDCP_hash("Hash not initialized");
	HashBuffer[index] = 0x80;
	if (index >= 56)
		compress();
	*((uint32_t*)(HashBuffer + 56)) = lenLo;
	*((uint32_t*)(HashBuffer + 60)) = lenHi;
	compress();
	memmove(digest, CurrentHash, sizeof(CurrentHash));
	burn();
}


void DCPh_ripemd160::compress()
{
	uint32_t X[16];
	uint32_t aa, bb, cc, dd, ee, aaa, bbb, ccc, ddd, eee;
	memset(X, 0, sizeof(X));
	memmove(X, HashBuffer, sizeof(X));

	aa = CurrentHash[0];
	aaa = CurrentHash[0];
	bb = CurrentHash[1];
	bbb = CurrentHash[1];
	cc = CurrentHash[2];
	ccc = CurrentHash[2];
	dd = CurrentHash[3];
	ddd = CurrentHash[3];
	ee = CurrentHash[4];
	eee = CurrentHash[4];

	aa = aa + (bb ^ cc ^ dd) + X[0];
	aa = ((aa << 11) | (aa >> (32 - 11))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + (aa ^ bb ^ cc) + X[1];
	ee = ((ee << 14) | (ee >> (32 - 14))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + (ee ^ aa ^ bb) + X[2];
	dd = ((dd << 15) | (dd >> (32 - 15))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + (dd ^ ee ^ aa) + X[3];
	cc = ((cc << 12) | (cc >> (32 - 12))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + (cc ^ dd ^ ee) + X[4];
	bb = ((bb << 5) | (bb >> (32 - 5))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + (bb ^ cc ^ dd) + X[5];
	aa = ((aa << 8) | (aa >> (32 - 8))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + (aa ^ bb ^ cc) + X[6];
	ee = ((ee << 7) | (ee >> (32 - 7))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + (ee ^ aa ^ bb) + X[7];
	dd = ((dd << 9) | (dd >> (32 - 9))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + (dd ^ ee ^ aa) + X[8];
	cc = ((cc << 11) | (cc >> (32 - 11))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + (cc ^ dd ^ ee) + X[9];
	bb = ((bb << 13) | (bb >> (32 - 13))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + (bb ^ cc ^ dd) + X[10];
	aa = ((aa << 14) | (aa >> (32 - 14))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + (aa ^ bb ^ cc) + X[11];
	ee = ((ee << 15) | (ee >> (32 - 15))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + (ee ^ aa ^ bb) + X[12];
	dd = ((dd << 6) | (dd >> (32 - 6))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + (dd ^ ee ^ aa) + X[13];
	cc = ((cc << 7) | (cc >> (32 - 7))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + (cc ^ dd ^ ee) + X[14];
	bb = ((bb << 9) | (bb >> (32 - 9))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + (bb ^ cc ^ dd) + X[15];
	aa = ((aa << 8) | (aa >> (32 - 8))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));

	ee = ee + ((aa & bb) | ((~aa) & cc)) + X[7] + 0x5a827999;
	ee = ((ee << 7) | (ee >> (32 - 7))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + ((ee & aa) | ((~ee) & bb)) + X[4] + 0x5a827999;
	dd = ((dd << 6) | (dd >> (32 - 6))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + ((dd & ee) | ((~dd) & aa)) + X[13] + 0x5a827999;
	cc = ((cc << 8) | (cc >> (32 - 8))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + ((cc & dd) | ((~cc) & ee)) + X[1] + 0x5a827999;
	bb = ((bb << 13) | (bb >> (32 - 13))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + ((bb & cc) | ((~bb) & dd)) + X[10] + 0x5a827999;
	aa = ((aa << 11) | (aa >> (32 - 11))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + ((aa & bb) | ((~aa) & cc)) + X[6] + 0x5a827999;
	ee = ((ee << 9) | (ee >> (32 - 9))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + ((ee & aa) | ((~ee) & bb)) + X[15] + 0x5a827999;
	dd = ((dd << 7) | (dd >> (32 - 7))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + ((dd & ee) | ((~dd) & aa)) + X[3] + 0x5a827999;
	cc = ((cc << 15) | (cc >> (32 - 15))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + ((cc & dd) | ((~cc) & ee)) + X[12] + 0x5a827999;
	bb = ((bb << 7) | (bb >> (32 - 7))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + ((bb & cc) | ((~bb) & dd)) + X[0] + 0x5a827999;
	aa = ((aa << 12) | (aa >> (32 - 12))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + ((aa & bb) | ((~aa) & cc)) + X[9] + 0x5a827999;
	ee = ((ee << 15) | (ee >> (32 - 15))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + ((ee & aa) | ((~ee) & bb)) + X[5] + 0x5a827999;
	dd = ((dd << 9) | (dd >> (32 - 9))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + ((dd & ee) | ((~dd) & aa)) + X[2] + 0x5a827999;
	cc = ((cc << 11) | (cc >> (32 - 11))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + ((cc & dd) | ((~cc) & ee)) + X[14] + 0x5a827999;
	bb = ((bb << 7) | (bb >> (32 - 7))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + ((bb & cc) | ((~bb) & dd)) + X[11] + 0x5a827999;
	aa = ((aa << 13) | (aa >> (32 - 13))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + ((aa & bb) | ((~aa) & cc)) + X[8] + 0x5a827999;
	ee = ((ee << 12) | (ee >> (32 - 12))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));

	dd = dd + ((ee | (~aa)) ^ bb) + X[3] + 0x6ed9eba1;
	dd = ((dd << 11) | (dd >> (32 - 11))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + ((dd | (~ee)) ^ aa) + X[10] + 0x6ed9eba1;
	cc = ((cc << 13) | (cc >> (32 - 13))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + ((cc | (~dd)) ^ ee) + X[14] + 0x6ed9eba1;
	bb = ((bb << 6) | (bb >> (32 - 6))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + ((bb | (~cc)) ^ dd) + X[4] + 0x6ed9eba1;
	aa = ((aa << 7) | (aa >> (32 - 7))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + ((aa | (~bb)) ^ cc) + X[9] + 0x6ed9eba1;
	ee = ((ee << 14) | (ee >> (32 - 14))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + ((ee | (~aa)) ^ bb) + X[15] + 0x6ed9eba1;
	dd = ((dd << 9) | (dd >> (32 - 9))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + ((dd | (~ee)) ^ aa) + X[8] + 0x6ed9eba1;
	cc = ((cc << 13) | (cc >> (32 - 13))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + ((cc | (~dd)) ^ ee) + X[1] + 0x6ed9eba1;
	bb = ((bb << 15) | (bb >> (32 - 15))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + ((bb | (~cc)) ^ dd) + X[2] + 0x6ed9eba1;
	aa = ((aa << 14) | (aa >> (32 - 14))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + ((aa | (~bb)) ^ cc) + X[7] + 0x6ed9eba1;
	ee = ((ee << 8) | (ee >> (32 - 8))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + ((ee | (~aa)) ^ bb) + X[0] + 0x6ed9eba1;
	dd = ((dd << 13) | (dd >> (32 - 13))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + ((dd | (~ee)) ^ aa) + X[6] + 0x6ed9eba1;
	cc = ((cc << 6) | (cc >> (32 - 6))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + ((cc | (~dd)) ^ ee) + X[13] + 0x6ed9eba1;
	bb = ((bb << 5) | (bb >> (32 - 5))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + ((bb | (~cc)) ^ dd) + X[11] + 0x6ed9eba1;
	aa = ((aa << 12) | (aa >> (32 - 12))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + ((aa | (~bb)) ^ cc) + X[5] + 0x6ed9eba1;
	ee = ((ee << 7) | (ee >> (32 - 7))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + ((ee | (~aa)) ^ bb) + X[12] + 0x6ed9eba1;
	dd = ((dd << 5) | (dd >> (32 - 5))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));

	cc = cc + ((dd & aa) | (ee & (~aa))) + X[1] + 0x8f1bbcdc;
	cc = ((cc << 11) | (cc >> (32 - 11))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + ((cc & ee) | (dd & (~ee))) + X[9] + 0x8f1bbcdc;
	bb = ((bb << 12) | (bb >> (32 - 12))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + ((bb & dd) | (cc & (~dd))) + X[11] + 0x8f1bbcdc;
	aa = ((aa << 14) | (aa >> (32 - 14))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + ((aa & cc) | (bb & (~cc))) + X[10] + 0x8f1bbcdc;
	ee = ((ee << 15) | (ee >> (32 - 15))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + ((ee & bb) | (aa & (~bb))) + X[0] + 0x8f1bbcdc;
	dd = ((dd << 14) | (dd >> (32 - 14))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + ((dd & aa) | (ee & (~aa))) + X[8] + 0x8f1bbcdc;
	cc = ((cc << 15) | (cc >> (32 - 15))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + ((cc & ee) | (dd & (~ee))) + X[12] + 0x8f1bbcdc;
	bb = ((bb << 9) | (bb >> (32 - 9))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + ((bb & dd) | (cc & (~dd))) + X[4] + 0x8f1bbcdc;
	aa = ((aa << 8) | (aa >> (32 - 8))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + ((aa & cc) | (bb & (~cc))) + X[13] + 0x8f1bbcdc;
	ee = ((ee << 9) | (ee >> (32 - 9))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + ((ee & bb) | (aa & (~bb))) + X[3] + 0x8f1bbcdc;
	dd = ((dd << 14) | (dd >> (32 - 14))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + ((dd & aa) | (ee & (~aa))) + X[7] + 0x8f1bbcdc;
	cc = ((cc << 5) | (cc >> (32 - 5))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + ((cc & ee) | (dd & (~ee))) + X[15] + 0x8f1bbcdc;
	bb = ((bb << 6) | (bb >> (32 - 6))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + ((bb & dd) | (cc & (~dd))) + X[14] + 0x8f1bbcdc;
	aa = ((aa << 8) | (aa >> (32 - 8))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + ((aa & cc) | (bb & (~cc))) + X[5] + 0x8f1bbcdc;
	ee = ((ee << 6) | (ee >> (32 - 6))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + ((ee & bb) | (aa & (~bb))) + X[6] + 0x8f1bbcdc;
	dd = ((dd << 5) | (dd >> (32 - 5))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + ((dd & aa) | (ee & (~aa))) + X[2] + 0x8f1bbcdc;
	cc = ((cc << 12) | (cc >> (32 - 12))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));

	bb = bb + (cc ^ (dd | (~ee))) + X[4] + 0xa953fd4e;
	bb = ((bb << 9) | (bb >> (32 - 9))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + (bb ^ (cc | (~dd))) + X[0] + 0xa953fd4e;
	aa = ((aa << 15) | (aa >> (32 - 15))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + (aa ^ (bb | (~cc))) + X[5] + 0xa953fd4e;
	ee = ((ee << 5) | (ee >> (32 - 5))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + (ee ^ (aa | (~bb))) + X[9] + 0xa953fd4e;
	dd = ((dd << 11) | (dd >> (32 - 11))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + (dd ^ (ee | (~aa))) + X[7] + 0xa953fd4e;
	cc = ((cc << 6) | (cc >> (32 - 6))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + (cc ^ (dd | (~ee))) + X[12] + 0xa953fd4e;
	bb = ((bb << 8) | (bb >> (32 - 8))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + (bb ^ (cc | (~dd))) + X[2] + 0xa953fd4e;
	aa = ((aa << 13) | (aa >> (32 - 13))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + (aa ^ (bb | (~cc))) + X[10] + 0xa953fd4e;
	ee = ((ee << 12) | (ee >> (32 - 12))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + (ee ^ (aa | (~bb))) + X[14] + 0xa953fd4e;
	dd = ((dd << 5) | (dd >> (32 - 5))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + (dd ^ (ee | (~aa))) + X[1] + 0xa953fd4e;
	cc = ((cc << 12) | (cc >> (32 - 12))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + (cc ^ (dd | (~ee))) + X[3] + 0xa953fd4e;
	bb = ((bb << 13) | (bb >> (32 - 13))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));
	aa = aa + (bb ^ (cc | (~dd))) + X[8] + 0xa953fd4e;
	aa = ((aa << 14) | (aa >> (32 - 14))) + ee;
	cc = ((cc << 10) | (cc >> (32 - 10)));
	ee = ee + (aa ^ (bb | (~cc))) + X[11] + 0xa953fd4e;
	ee = ((ee << 11) | (ee >> (32 - 11))) + dd;
	bb = ((bb << 10) | (bb >> (32 - 10)));
	dd = dd + (ee ^ (aa | (~bb))) + X[6] + 0xa953fd4e;
	dd = ((dd << 8) | (dd >> (32 - 8))) + cc;
	aa = ((aa << 10) | (aa >> (32 - 10)));
	cc = cc + (dd ^ (ee | (~aa))) + X[15] + 0xa953fd4e;
	cc = ((cc << 5) | (cc >> (32 - 5))) + bb;
	ee = ((ee << 10) | (ee >> (32 - 10)));
	bb = bb + (cc ^ (dd | (~ee))) + X[13] + 0xa953fd4e;
	bb = ((bb << 6) | (bb >> (32 - 6))) + aa;
	dd = ((dd << 10) | (dd >> (32 - 10)));

	aaa = aaa + (bbb ^ (ccc | (~ddd))) + X[5] + 0x50a28be6;
	aaa = ((aaa << 8) | (aaa >> (32 - 8))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + (aaa ^ (bbb | (~ccc))) + X[14] + 0x50a28be6;
	eee = ((eee << 9) | (eee >> (32 - 9))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + (eee ^ (aaa | (~bbb))) + X[7] + 0x50a28be6;
	ddd = ((ddd << 9) | (ddd >> (32 - 9))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + (ddd ^ (eee | (~aaa))) + X[0] + 0x50a28be6;
	ccc = ((ccc << 11) | (ccc >> (32 - 11))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + (ccc ^ (ddd | (~eee))) + X[9] + 0x50a28be6;
	bbb = ((bbb << 13) | (bbb >> (32 - 13))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + (bbb ^ (ccc | (~ddd))) + X[2] + 0x50a28be6;
	aaa = ((aaa << 15) | (aaa >> (32 - 15))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + (aaa ^ (bbb | (~ccc))) + X[11] + 0x50a28be6;
	eee = ((eee << 15) | (eee >> (32 - 15))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + (eee ^ (aaa | (~bbb))) + X[4] + 0x50a28be6;
	ddd = ((ddd << 5) | (ddd >> (32 - 5))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + (ddd ^ (eee | (~aaa))) + X[13] + 0x50a28be6;
	ccc = ((ccc << 7) | (ccc >> (32 - 7))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + (ccc ^ (ddd | (~eee))) + X[6] + 0x50a28be6;
	bbb = ((bbb << 7) | (bbb >> (32 - 7))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + (bbb ^ (ccc | (~ddd))) + X[15] + 0x50a28be6;
	aaa = ((aaa << 8) | (aaa >> (32 - 8))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + (aaa ^ (bbb | (~ccc))) + X[8] + 0x50a28be6;
	eee = ((eee << 11) | (eee >> (32 - 11))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + (eee ^ (aaa | (~bbb))) + X[1] + 0x50a28be6;
	ddd = ((ddd << 14) | (ddd >> (32 - 14))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + (ddd ^ (eee | (~aaa))) + X[10] + 0x50a28be6;
	ccc = ((ccc << 14) | (ccc >> (32 - 14))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + (ccc ^ (ddd | (~eee))) + X[3] + 0x50a28be6;
	bbb = ((bbb << 12) | (bbb >> (32 - 12))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + (bbb ^ (ccc | (~ddd))) + X[12] + 0x50a28be6;
	aaa = ((aaa << 6) | (aaa >> (32 - 6))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));

	eee = eee + ((aaa & ccc) | (bbb & (~ccc))) + X[6] + 0x5c4dd124;
	eee = ((eee << 9) | (eee >> (32 - 9))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + ((eee & bbb) | (aaa & (~bbb))) + X[11] + 0x5c4dd124;
	ddd = ((ddd << 13) | (ddd >> (32 - 13))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + ((ddd & aaa) | (eee & (~aaa))) + X[3] + 0x5c4dd124;
	ccc = ((ccc << 15) | (ccc >> (32 - 15))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + ((ccc & eee) | (ddd & (~eee))) + X[7] + 0x5c4dd124;
	bbb = ((bbb << 7) | (bbb >> (32 - 7))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + ((bbb & ddd) | (ccc & (~ddd))) + X[0] + 0x5c4dd124;
	aaa = ((aaa << 12) | (aaa >> (32 - 12))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + ((aaa & ccc) | (bbb & (~ccc))) + X[13] + 0x5c4dd124;
	eee = ((eee << 8) | (eee >> (32 - 8))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + ((eee & bbb) | (aaa & (~bbb))) + X[5] + 0x5c4dd124;
	ddd = ((ddd << 9) | (ddd >> (32 - 9))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + ((ddd & aaa) | (eee & (~aaa))) + X[10] + 0x5c4dd124;
	ccc = ((ccc << 11) | (ccc >> (32 - 11))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + ((ccc & eee) | (ddd & (~eee))) + X[14] + 0x5c4dd124;
	bbb = ((bbb << 7) | (bbb >> (32 - 7))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + ((bbb & ddd) | (ccc & (~ddd))) + X[15] + 0x5c4dd124;
	aaa = ((aaa << 7) | (aaa >> (32 - 7))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + ((aaa & ccc) | (bbb & (~ccc))) + X[8] + 0x5c4dd124;
	eee = ((eee << 12) | (eee >> (32 - 12))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + ((eee & bbb) | (aaa & (~bbb))) + X[12] + 0x5c4dd124;
	ddd = ((ddd << 7) | (ddd >> (32 - 7))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + ((ddd & aaa) | (eee & (~aaa))) + X[4] + 0x5c4dd124;
	ccc = ((ccc << 6) | (ccc >> (32 - 6))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + ((ccc & eee) | (ddd & (~eee))) + X[9] + 0x5c4dd124;
	bbb = ((bbb << 15) | (bbb >> (32 - 15))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + ((bbb & ddd) | (ccc & (~ddd))) + X[1] + 0x5c4dd124;
	aaa = ((aaa << 13) | (aaa >> (32 - 13))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + ((aaa & ccc) | (bbb & (~ccc))) + X[2] + 0x5c4dd124;
	eee = ((eee << 11) | (eee >> (32 - 11))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));

	ddd = ddd + ((eee | (~aaa)) ^ bbb) + X[15] + 0x6d703ef3;
	ddd = ((ddd << 9) | (ddd >> (32 - 9))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + ((ddd | (~eee)) ^ aaa) + X[5] + 0x6d703ef3;
	ccc = ((ccc << 7) | (ccc >> (32 - 7))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + ((ccc | (~ddd)) ^ eee) + X[1] + 0x6d703ef3;
	bbb = ((bbb << 15) | (bbb >> (32 - 15))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + ((bbb | (~ccc)) ^ ddd) + X[3] + 0x6d703ef3;
	aaa = ((aaa << 11) | (aaa >> (32 - 11))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + ((aaa | (~bbb)) ^ ccc) + X[7] + 0x6d703ef3;
	eee = ((eee << 8) | (eee >> (32 - 8))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + ((eee | (~aaa)) ^ bbb) + X[14] + 0x6d703ef3;
	ddd = ((ddd << 6) | (ddd >> (32 - 6))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + ((ddd | (~eee)) ^ aaa) + X[6] + 0x6d703ef3;
	ccc = ((ccc << 6) | (ccc >> (32 - 6))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + ((ccc | (~ddd)) ^ eee) + X[9] + 0x6d703ef3;
	bbb = ((bbb << 14) | (bbb >> (32 - 14))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + ((bbb | (~ccc)) ^ ddd) + X[11] + 0x6d703ef3;
	aaa = ((aaa << 12) | (aaa >> (32 - 12))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + ((aaa | (~bbb)) ^ ccc) + X[8] + 0x6d703ef3;
	eee = ((eee << 13) | (eee >> (32 - 13))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + ((eee | (~aaa)) ^ bbb) + X[12] + 0x6d703ef3;
	ddd = ((ddd << 5) | (ddd >> (32 - 5))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + ((ddd | (~eee)) ^ aaa) + X[2] + 0x6d703ef3;
	ccc = ((ccc << 14) | (ccc >> (32 - 14))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + ((ccc | (~ddd)) ^ eee) + X[10] + 0x6d703ef3;
	bbb = ((bbb << 13) | (bbb >> (32 - 13))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + ((bbb | (~ccc)) ^ ddd) + X[0] + 0x6d703ef3;
	aaa = ((aaa << 13) | (aaa >> (32 - 13))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + ((aaa | (~bbb)) ^ ccc) + X[4] + 0x6d703ef3;
	eee = ((eee << 7) | (eee >> (32 - 7))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + ((eee | (~aaa)) ^ bbb) + X[13] + 0x6d703ef3;
	ddd = ((ddd << 5) | (ddd >> (32 - 5))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));

	ccc = ccc + ((ddd & eee) | ((~ddd) & aaa)) + X[8] + 0x7a6d76e9;
	ccc = ((ccc << 15) | (ccc >> (32 - 15))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + ((ccc & ddd) | ((~ccc) & eee)) + X[6] + 0x7a6d76e9;
	bbb = ((bbb << 5) | (bbb >> (32 - 5))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + ((bbb & ccc) | ((~bbb) & ddd)) + X[4] + 0x7a6d76e9;
	aaa = ((aaa << 8) | (aaa >> (32 - 8))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + ((aaa & bbb) | ((~aaa) & ccc)) + X[1] + 0x7a6d76e9;
	eee = ((eee << 11) | (eee >> (32 - 11))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + ((eee & aaa) | ((~eee) & bbb)) + X[3] + 0x7a6d76e9;
	ddd = ((ddd << 14) | (ddd >> (32 - 14))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + ((ddd & eee) | ((~ddd) & aaa)) + X[11] + 0x7a6d76e9;
	ccc = ((ccc << 14) | (ccc >> (32 - 14))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + ((ccc & ddd) | ((~ccc) & eee)) + X[15] + 0x7a6d76e9;
	bbb = ((bbb << 6) | (bbb >> (32 - 6))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + ((bbb & ccc) | ((~bbb) & ddd)) + X[0] + 0x7a6d76e9;
	aaa = ((aaa << 14) | (aaa >> (32 - 14))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + ((aaa & bbb) | ((~aaa) & ccc)) + X[5] + 0x7a6d76e9;
	eee = ((eee << 6) | (eee >> (32 - 6))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + ((eee & aaa) | ((~eee) & bbb)) + X[12] + 0x7a6d76e9;
	ddd = ((ddd << 9) | (ddd >> (32 - 9))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + ((ddd & eee) | ((~ddd) & aaa)) + X[2] + 0x7a6d76e9;
	ccc = ((ccc << 12) | (ccc >> (32 - 12))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + ((ccc & ddd) | ((~ccc) & eee)) + X[13] + 0x7a6d76e9;
	bbb = ((bbb << 9) | (bbb >> (32 - 9))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + ((bbb & ccc) | ((~bbb) & ddd)) + X[9] + 0x7a6d76e9;
	aaa = ((aaa << 12) | (aaa >> (32 - 12))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + ((aaa & bbb) | ((~aaa) & ccc)) + X[7] + 0x7a6d76e9;
	eee = ((eee << 5) | (eee >> (32 - 5))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + ((eee & aaa) | ((~eee) & bbb)) + X[10] + 0x7a6d76e9;
	ddd = ((ddd << 15) | (ddd >> (32 - 15))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + ((ddd & eee) | ((~ddd) & aaa)) + X[14] + 0x7a6d76e9;
	ccc = ((ccc << 8) | (ccc >> (32 - 8))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));

	bbb = bbb + (ccc ^ ddd ^ eee) + X[12];
	bbb = ((bbb << 8) | (bbb >> (32 - 8))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + (bbb ^ ccc ^ ddd) + X[15];
	aaa = ((aaa << 5) | (aaa >> (32 - 5))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + (aaa ^ bbb ^ ccc) + X[10];
	eee = ((eee << 12) | (eee >> (32 - 12))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + (eee ^ aaa ^ bbb) + X[4];
	ddd = ((ddd << 9) | (ddd >> (32 - 9))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + (ddd ^ eee ^ aaa) + X[1];
	ccc = ((ccc << 12) | (ccc >> (32 - 12))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + (ccc ^ ddd ^ eee) + X[5];
	bbb = ((bbb << 5) | (bbb >> (32 - 5))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + (bbb ^ ccc ^ ddd) + X[8];
	aaa = ((aaa << 14) | (aaa >> (32 - 14))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + (aaa ^ bbb ^ ccc) + X[7];
	eee = ((eee << 6) | (eee >> (32 - 6))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + (eee ^ aaa ^ bbb) + X[6];
	ddd = ((ddd << 8) | (ddd >> (32 - 8))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + (ddd ^ eee ^ aaa) + X[2];
	ccc = ((ccc << 13) | (ccc >> (32 - 13))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + (ccc ^ ddd ^ eee) + X[13];
	bbb = ((bbb << 6) | (bbb >> (32 - 6))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));
	aaa = aaa + (bbb ^ ccc ^ ddd) + X[14];
	aaa = ((aaa << 5) | (aaa >> (32 - 5))) + eee;
	ccc = ((ccc << 10) | (ccc >> (32 - 10)));
	eee = eee + (aaa ^ bbb ^ ccc) + X[0];
	eee = ((eee << 15) | (eee >> (32 - 15))) + ddd;
	bbb = ((bbb << 10) | (bbb >> (32 - 10)));
	ddd = ddd + (eee ^ aaa ^ bbb) + X[3];
	ddd = ((ddd << 13) | (ddd >> (32 - 13))) + ccc;
	aaa = ((aaa << 10) | (aaa >> (32 - 10)));
	ccc = ccc + (ddd ^ eee ^ aaa) + X[9];
	ccc = ((ccc << 11) | (ccc >> (32 - 11))) + bbb;
	eee = ((eee << 10) | (eee >> (32 - 10)));
	bbb = bbb + (ccc ^ ddd ^ eee) + X[11];
	bbb = ((bbb << 11) | (bbb >> (32 - 11))) + aaa;
	ddd = ((ddd << 10) | (ddd >> (32 - 10)));

	ddd = ddd + cc + CurrentHash[1];
	CurrentHash[1] = CurrentHash[2] + dd + eee;
	CurrentHash[2] = CurrentHash[3] + ee + aaa;
	CurrentHash[3] = CurrentHash[4] + aa + bbb;
	CurrentHash[4] = CurrentHash[0] + bb + ccc;
	CurrentHash[0] = ddd;

	memset(X, 0, sizeof(X));
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
}

