//see https://md5calc.com/hash, http://www.unit-conversion.info/texttools/haval/
#include "DCPh_haval.h"
#include "Exception.h"
#include "Util.h"
#define HAVAL_VERSION 1

using namespace std;
using namespace dcpcrypt;

DCPh_haval::DCPh_haval(int digestBits, int passCount) :digestBits(digestBits), passCount(passCount)
{
}


DCPh_haval::~DCPh_haval()
{
};


#define f_1(x6, x5, x4, x3, x2, x1, x0)          \
           ((x1) & ((x0) ^ (x4)) ^ (x2) & (x5) ^ \
            (x3) & (x6) ^ (x0))

#define f_2(x6, x5, x4, x3, x2, x1, x0)                         \
           ((x2) & ((x1) & ~(x3) ^ (x4) & (x5) ^ (x6) ^ (x0)) ^ \
            (x4) & ((x1) ^ (x5)) ^ (x3) & (x5) ^ (x0))

#define f_3(x6, x5, x4, x3, x2, x1, x0)          \
           ((x3) & ((x1) & (x2) ^ (x6) ^ (x0)) ^ \
            (x1) & (x4) ^ (x2) & (x5) ^ (x0))

#define f_4(x6, x5, x4, x3, x2, x1, x0)                                 \
           ((x4) & ((x5) & ~(x2) ^ (x3) & ~(x6) ^ (x1) ^ (x6) ^ (x0)) ^ \
            (x3) & ((x1) & (x2) ^ (x5) ^ (x6)) ^                        \
            (x2) & (x6) ^ (x0))

#define f_5(x6, x5, x4, x3, x2, x1, x0)             \
           ((x0) & ((x1) & (x2) & (x3) ^ ~(x5)) ^   \
            (x1) & (x4) ^ (x2) & (x5) ^ (x3) & (x6))

/*
* Permutations phi_{i,j}, i=3,4,5, j=1,...,i.
*
* PASS = 3:
*               6 5 4 3 2 1 0
*               | | | | | | | (replaced by)
*  phi_{3,1}:   1 0 3 5 6 2 4
*  phi_{3,2}:   4 2 1 0 5 3 6
*  phi_{3,3}:   6 1 2 3 4 5 0
*
* PASS = 4:
*               6 5 4 3 2 1 0
*               | | | | | | | (replaced by)
*  phi_{4,1}:   2 6 1 4 5 3 0
*  phi_{4,2}:   3 5 2 0 1 6 4
*  phi_{4,3}:   1 4 3 6 0 2 5
*  phi_{4,4}:   6 4 0 5 2 1 3
*
* PASS = 5:
*               6 5 4 3 2 1 0
*               | | | | | | | (replaced by)
*  phi_{5,1}:   3 4 1 0 5 2 6
*  phi_{5,2}:   6 2 1 0 3 4 5
*  phi_{5,3}:   2 6 0 4 3 1 5
*  phi_{5,4}:   1 5 3 2 0 4 6
*  phi_{5,5}:   2 5 0 6 4 3 1
*/

#define Fphi_1_3(x6, x5, x4, x3, x2, x1, x0) \
           f_1(x1, x0, x3, x5, x6, x2, x4)
#define Fphi_1_4(x6, x5, x4, x3, x2, x1, x0) \
           f_1(x2, x6, x1, x4, x5, x3, x0)
#define Fphi_1_5(x6, x5, x4, x3, x2, x1, x0) \
           f_1(x3, x4, x1, x0, x5, x2, x6)

#define Fphi_2_3(x6, x5, x4, x3, x2, x1, x0) \
           f_2(x4, x2, x1, x0, x5, x3, x6)
#define Fphi_2_4(x6, x5, x4, x3, x2, x1, x0) \
           f_2(x3, x5, x2, x0, x1, x6, x4)
#define Fphi_2_5(x6, x5, x4, x3, x2, x1, x0) \
           f_2(x6, x2, x1, x0, x3, x4, x5)


#define Fphi_3_3(x6, x5, x4, x3, x2, x1, x0) \
           f_3(x6, x1, x2, x3, x4, x5, x0)
#define Fphi_3_4(x6, x5, x4, x3, x2, x1, x0) \
           f_3(x1, x4, x3, x6, x0, x2, x5)
#define Fphi_3_5(x6, x5, x4, x3, x2, x1, x0) \
           f_3(x2, x6, x0, x4, x3, x1, x5)


#define Fphi_4_4(x6, x5, x4, x3, x2, x1, x0) \
           f_4(x6, x4, x0, x5, x2, x1, x3)
#define Fphi_4_5(x6, x5, x4, x3, x2, x1, x0) \
            f_4(x1, x5, x3, x2, x0, x4, x6)

#define Fphi_5(x6, x5, x4, x3, x2, x1, x0) \
           f_5(x2, x5, x0, x6, x4, x3, x1)

#define rotate_right(x, n) (((x) >> (n)) | ((x) << (32-(n))))

#define FF_1_3(x7, x6, x5, x4, x3, x2, x1, x0, w) {                        \
      register uint32_t temp = Fphi_1_3(x6, x5, x4, x3, x2, x1, x0);     \
      (x7) = rotate_right(temp, 7) + rotate_right((x7), 11) + (w);       \
      }
#define FF_1_4(x7, x6, x5, x4, x3, x2, x1, x0, w) {                        \
      register uint32_t temp = Fphi_1_4(x6, x5, x4, x3, x2, x1, x0);     \
      (x7) = rotate_right(temp, 7) + rotate_right((x7), 11) + (w);       \
      }
#define FF_1_5(x7, x6, x5, x4, x3, x2, x1, x0, w) {                        \
      register uint32_t temp = Fphi_1_5(x6, x5, x4, x3, x2, x1, x0);     \
      (x7) = rotate_right(temp, 7) + rotate_right((x7), 11) + (w);       \
      }


#define FF_2_3(x7, x6, x5, x4, x3, x2, x1, x0, w, c) {                      \
      register uint32_t temp = Fphi_2_3(x6, x5, x4, x3, x2, x1, x0);      \
      (x7) = rotate_right(temp, 7) + rotate_right((x7), 11) + (w) + (c);  \
      }
#define FF_2_4(x7, x6, x5, x4, x3, x2, x1, x0, w, c) {                      \
      register uint32_t temp = Fphi_2_4(x6, x5, x4, x3, x2, x1, x0);      \
      (x7) = rotate_right(temp, 7) + rotate_right((x7), 11) + (w) + (c);  \
      }
#define FF_2_5(x7, x6, x5, x4, x3, x2, x1, x0, w, c) {                      \
      register uint32_t temp = Fphi_2_5(x6, x5, x4, x3, x2, x1, x0);      \
      (x7) = rotate_right(temp, 7) + rotate_right((x7), 11) + (w) + (c);  \
      }

#define FF_3_3(x7, x6, x5, x4, x3, x2, x1, x0, w, c) {                      \
      register uint32_t temp = Fphi_3_3(x6, x5, x4, x3, x2, x1, x0);      \
      (x7) = rotate_right(temp, 7) + rotate_right((x7), 11) + (w) + (c);  \
      }
#define FF_3_4(x7, x6, x5, x4, x3, x2, x1, x0, w, c) {                      \
      register uint32_t temp = Fphi_3_4(x6, x5, x4, x3, x2, x1, x0);      \
      (x7) = rotate_right(temp, 7) + rotate_right((x7), 11) + (w) + (c);  \
      }
#define FF_3_5(x7, x6, x5, x4, x3, x2, x1, x0, w, c) {                      \
      register uint32_t temp = Fphi_3_5(x6, x5, x4, x3, x2, x1, x0);      \
      (x7) = rotate_right(temp, 7) + rotate_right((x7), 11) + (w) + (c);  \
      }

#define FF_4_4(x7, x6, x5, x4, x3, x2, x1, x0, w, c) {                      \
      register uint32_t temp = Fphi_4_4(x6, x5, x4, x3, x2, x1, x0);      \
      (x7) = rotate_right(temp, 7) + rotate_right((x7), 11) + (w) + (c);  \
      }
#define FF_4_5(x7, x6, x5, x4, x3, x2, x1, x0, w, c) {                      \
      register uint32_t temp = Fphi_4_5(x6, x5, x4, x3, x2, x1, x0);      \
      (x7) = rotate_right(temp, 7) + rotate_right((x7), 11) + (w) + (c);  \
      }

#define FF_5(x7, x6, x5, x4, x3, x2, x1, x0, w, c) {                      \
      register uint32_t temp = Fphi_5(x6, x5, x4, x3, x2, x1, x0);      \
      (x7) = rotate_right(temp, 7) + rotate_right((x7), 11) + (w) + (c);  \
      }


void DCPh_haval::compress()
{
	register uint32_t t0 = CurrentHash[0],    // make use of
		t1 = CurrentHash[1],    // internal registers
		t2 = CurrentHash[2],
		t3 = CurrentHash[3],
		t4 = CurrentHash[4],
		t5 = CurrentHash[5],
		t6 = CurrentHash[6],
		t7 = CurrentHash[7],
		*w = (uint32_t*)HashBuffer;

	if (passCount == 3)
	{
		// Pass 1
		FF_1_3(t7, t6, t5, t4, t3, t2, t1, t0, *(w));
		FF_1_3(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 1));
		FF_1_3(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 2));
		FF_1_3(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 3));
		FF_1_3(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 4));
		FF_1_3(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 5));
		FF_1_3(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 6));
		FF_1_3(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 7));

		FF_1_3(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 8));
		FF_1_3(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 9));
		FF_1_3(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 10));
		FF_1_3(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 11));
		FF_1_3(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 12));
		FF_1_3(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 13));
		FF_1_3(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 14));
		FF_1_3(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 15));

		FF_1_3(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 16));
		FF_1_3(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 17));
		FF_1_3(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 18));
		FF_1_3(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 19));
		FF_1_3(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 20));
		FF_1_3(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 21));
		FF_1_3(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 22));
		FF_1_3(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 23));

		FF_1_3(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 24));
		FF_1_3(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 25));
		FF_1_3(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 26));
		FF_1_3(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 27));
		FF_1_3(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 28));
		FF_1_3(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 29));
		FF_1_3(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 30));
		FF_1_3(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 31));

		// Pass 2
		FF_2_3(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 5), 0x452821E6L);
		FF_2_3(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 14), 0x38D01377L);
		FF_2_3(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 26), 0xBE5466CFL);
		FF_2_3(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 18), 0x34E90C6CL);
		FF_2_3(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 11), 0xC0AC29B7L);
		FF_2_3(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 28), 0xC97C50DDL);
		FF_2_3(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 7), 0x3F84D5B5L);
		FF_2_3(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 16), 0xB5470917L);

		FF_2_3(t7, t6, t5, t4, t3, t2, t1, t0, *(w), 0x9216D5D9L);
		FF_2_3(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 23), 0x8979FB1BL);
		FF_2_3(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 20), 0xD1310BA6L);
		FF_2_3(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 22), 0x98DFB5ACL);
		FF_2_3(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 1), 0x2FFD72DBL);
		FF_2_3(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 10), 0xD01ADFB7L);
		FF_2_3(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 4), 0xB8E1AFEDL);
		FF_2_3(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 8), 0x6A267E96L);

		FF_2_3(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 30), 0xBA7C9045L);
		FF_2_3(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 3), 0xF12C7F99L);
		FF_2_3(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 21), 0x24A19947L);
		FF_2_3(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 9), 0xB3916CF7L);
		FF_2_3(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 17), 0x0801F2E2L);
		FF_2_3(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 24), 0x858EFC16L);
		FF_2_3(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 29), 0x636920D8L);
		FF_2_3(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 6), 0x71574E69L);

		FF_2_3(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 19), 0xA458FEA3L);
		FF_2_3(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 12), 0xF4933D7EL);
		FF_2_3(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 15), 0x0D95748FL);
		FF_2_3(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 13), 0x728EB658L);
		FF_2_3(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 2), 0x718BCD58L);
		FF_2_3(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 25), 0x82154AEEL);
		FF_2_3(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 31), 0x7B54A41DL);
		FF_2_3(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 27), 0xC25A59B5L);

		// Pass 3
		FF_3_3(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 19), 0x9C30D539L);
		FF_3_3(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 9), 0x2AF26013L);
		FF_3_3(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 4), 0xC5D1B023L);
		FF_3_3(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 20), 0x286085F0L);
		FF_3_3(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 28), 0xCA417918L);
		FF_3_3(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 17), 0xB8DB38EFL);
		FF_3_3(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 8), 0x8E79DCB0L);
		FF_3_3(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 22), 0x603A180EL);

		FF_3_3(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 29), 0x6C9E0E8BL);
		FF_3_3(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 14), 0xB01E8A3EL);
		FF_3_3(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 25), 0xD71577C1L);
		FF_3_3(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 12), 0xBD314B27L);
		FF_3_3(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 24), 0x78AF2FDAL);
		FF_3_3(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 30), 0x55605C60L);
		FF_3_3(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 16), 0xE65525F3L);
		FF_3_3(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 26), 0xAA55AB94L);

		FF_3_3(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 31), 0x57489862L);
		FF_3_3(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 15), 0x63E81440L);
		FF_3_3(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 7), 0x55CA396AL);
		FF_3_3(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 3), 0x2AAB10B6L);
		FF_3_3(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 1), 0xB4CC5C34L);
		FF_3_3(t2, t1, t0, t7, t6, t5, t4, t3, *(w), 0x1141E8CEL);
		FF_3_3(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 18), 0xA15486AFL);
		FF_3_3(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 27), 0x7C72E993L);

		FF_3_3(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 13), 0xB3EE1411L);
		FF_3_3(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 6), 0x636FBC2AL);
		FF_3_3(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 21), 0x2BA9C55DL);
		FF_3_3(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 10), 0x741831F6L);
		FF_3_3(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 23), 0xCE5C3E16L);
		FF_3_3(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 11), 0x9B87931EL);
		FF_3_3(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 5), 0xAFD6BA33L);
		FF_3_3(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 2), 0x6C24CF5CL);
	}
	else if (passCount == 4)
	{
		// Pass 1
		FF_1_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w));
		FF_1_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 1));
		FF_1_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 2));
		FF_1_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 3));
		FF_1_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 4));
		FF_1_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 5));
		FF_1_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 6));
		FF_1_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 7));

		FF_1_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 8));
		FF_1_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 9));
		FF_1_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 10));
		FF_1_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 11));
		FF_1_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 12));
		FF_1_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 13));
		FF_1_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 14));
		FF_1_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 15));

		FF_1_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 16));
		FF_1_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 17));
		FF_1_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 18));
		FF_1_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 19));
		FF_1_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 20));
		FF_1_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 21));
		FF_1_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 22));
		FF_1_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 23));

		FF_1_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 24));
		FF_1_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 25));
		FF_1_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 26));
		FF_1_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 27));
		FF_1_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 28));
		FF_1_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 29));
		FF_1_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 30));
		FF_1_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 31));

		// Pass 2
		FF_2_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 5), 0x452821E6L);
		FF_2_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 14), 0x38D01377L);
		FF_2_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 26), 0xBE5466CFL);
		FF_2_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 18), 0x34E90C6CL);
		FF_2_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 11), 0xC0AC29B7L);
		FF_2_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 28), 0xC97C50DDL);
		FF_2_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 7), 0x3F84D5B5L);
		FF_2_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 16), 0xB5470917L);

		FF_2_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w), 0x9216D5D9L);
		FF_2_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 23), 0x8979FB1BL);
		FF_2_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 20), 0xD1310BA6L);
		FF_2_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 22), 0x98DFB5ACL);
		FF_2_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 1), 0x2FFD72DBL);
		FF_2_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 10), 0xD01ADFB7L);
		FF_2_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 4), 0xB8E1AFEDL);
		FF_2_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 8), 0x6A267E96L);

		FF_2_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 30), 0xBA7C9045L);
		FF_2_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 3), 0xF12C7F99L);
		FF_2_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 21), 0x24A19947L);
		FF_2_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 9), 0xB3916CF7L);
		FF_2_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 17), 0x0801F2E2L);
		FF_2_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 24), 0x858EFC16L);
		FF_2_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 29), 0x636920D8L);
		FF_2_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 6), 0x71574E69L);

		FF_2_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 19), 0xA458FEA3L);
		FF_2_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 12), 0xF4933D7EL);
		FF_2_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 15), 0x0D95748FL);
		FF_2_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 13), 0x728EB658L);
		FF_2_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 2), 0x718BCD58L);
		FF_2_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 25), 0x82154AEEL);
		FF_2_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 31), 0x7B54A41DL);
		FF_2_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 27), 0xC25A59B5L);

		// Pass 3
		FF_3_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 19), 0x9C30D539L);
		FF_3_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 9), 0x2AF26013L);
		FF_3_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 4), 0xC5D1B023L);
		FF_3_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 20), 0x286085F0L);
		FF_3_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 28), 0xCA417918L);
		FF_3_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 17), 0xB8DB38EFL);
		FF_3_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 8), 0x8E79DCB0L);
		FF_3_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 22), 0x603A180EL);

		FF_3_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 29), 0x6C9E0E8BL);
		FF_3_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 14), 0xB01E8A3EL);
		FF_3_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 25), 0xD71577C1L);
		FF_3_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 12), 0xBD314B27L);
		FF_3_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 24), 0x78AF2FDAL);
		FF_3_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 30), 0x55605C60L);
		FF_3_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 16), 0xE65525F3L);
		FF_3_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 26), 0xAA55AB94L);

		FF_3_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 31), 0x57489862L);
		FF_3_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 15), 0x63E81440L);
		FF_3_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 7), 0x55CA396AL);
		FF_3_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 3), 0x2AAB10B6L);
		FF_3_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 1), 0xB4CC5C34L);
		FF_3_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w), 0x1141E8CEL);
		FF_3_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 18), 0xA15486AFL);
		FF_3_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 27), 0x7C72E993L);

		FF_3_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 13), 0xB3EE1411L);
		FF_3_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 6), 0x636FBC2AL);
		FF_3_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 21), 0x2BA9C55DL);
		FF_3_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 10), 0x741831F6L);
		FF_3_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 23), 0xCE5C3E16L);
		FF_3_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 11), 0x9B87931EL);
		FF_3_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 5), 0xAFD6BA33L);
		FF_3_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 2), 0x6C24CF5CL);

		// Pass 4. executed only when PASS =4 or 5
		FF_4_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 24), 0x7A325381L);
		FF_4_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 4), 0x28958677L);
		FF_4_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w), 0x3B8F4898L);
		FF_4_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 14), 0x6B4BB9AFL);
		FF_4_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 2), 0xC4BFE81BL);
		FF_4_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 7), 0x66282193L);
		FF_4_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 28), 0x61D809CCL);
		FF_4_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 23), 0xFB21A991L);

		FF_4_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 26), 0x487CAC60L);
		FF_4_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 6), 0x5DEC8032L);
		FF_4_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 30), 0xEF845D5DL);
		FF_4_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 20), 0xE98575B1L);
		FF_4_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 18), 0xDC262302L);
		FF_4_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 25), 0xEB651B88L);
		FF_4_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 19), 0x23893E81L);
		FF_4_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 3), 0xD396ACC5L);

		FF_4_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 22), 0x0F6D6FF3L);
		FF_4_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 11), 0x83F44239L);
		FF_4_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 31), 0x2E0B4482L);
		FF_4_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 21), 0xA4842004L);
		FF_4_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 8), 0x69C8F04AL);
		FF_4_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 27), 0x9E1F9B5EL);
		FF_4_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 12), 0x21C66842L);
		FF_4_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 9), 0xF6E96C9AL);

		FF_4_4(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 1), 0x670C9C61L);
		FF_4_4(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 29), 0xABD388F0L);
		FF_4_4(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 5), 0x6A51A0D2L);
		FF_4_4(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 15), 0xD8542F68L);
		FF_4_4(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 17), 0x960FA728L);
		FF_4_4(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 10), 0xAB5133A3L);
		FF_4_4(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 16), 0x6EEF0B6CL);
		FF_4_4(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 13), 0x137A3BE4L);
	}
	else if (passCount == 5)
	{
		// Pass 1
		FF_1_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w));
		FF_1_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 1));
		FF_1_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 2));
		FF_1_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 3));
		FF_1_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 4));
		FF_1_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 5));
		FF_1_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 6));
		FF_1_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 7));

		FF_1_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 8));
		FF_1_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 9));
		FF_1_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 10));
		FF_1_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 11));
		FF_1_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 12));
		FF_1_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 13));
		FF_1_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 14));
		FF_1_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 15));

		FF_1_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 16));
		FF_1_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 17));
		FF_1_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 18));
		FF_1_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 19));
		FF_1_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 20));
		FF_1_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 21));
		FF_1_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 22));
		FF_1_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 23));

		FF_1_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 24));
		FF_1_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 25));
		FF_1_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 26));
		FF_1_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 27));
		FF_1_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 28));
		FF_1_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 29));
		FF_1_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 30));
		FF_1_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 31));

		// Pass 2
		FF_2_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 5), 0x452821E6L);
		FF_2_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 14), 0x38D01377L);
		FF_2_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 26), 0xBE5466CFL);
		FF_2_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 18), 0x34E90C6CL);
		FF_2_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 11), 0xC0AC29B7L);
		FF_2_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 28), 0xC97C50DDL);
		FF_2_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 7), 0x3F84D5B5L);
		FF_2_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 16), 0xB5470917L);

		FF_2_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w), 0x9216D5D9L);
		FF_2_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 23), 0x8979FB1BL);
		FF_2_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 20), 0xD1310BA6L);
		FF_2_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 22), 0x98DFB5ACL);
		FF_2_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 1), 0x2FFD72DBL);
		FF_2_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 10), 0xD01ADFB7L);
		FF_2_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 4), 0xB8E1AFEDL);
		FF_2_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 8), 0x6A267E96L);

		FF_2_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 30), 0xBA7C9045L);
		FF_2_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 3), 0xF12C7F99L);
		FF_2_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 21), 0x24A19947L);
		FF_2_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 9), 0xB3916CF7L);
		FF_2_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 17), 0x0801F2E2L);
		FF_2_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 24), 0x858EFC16L);
		FF_2_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 29), 0x636920D8L);
		FF_2_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 6), 0x71574E69L);

		FF_2_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 19), 0xA458FEA3L);
		FF_2_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 12), 0xF4933D7EL);
		FF_2_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 15), 0x0D95748FL);
		FF_2_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 13), 0x728EB658L);
		FF_2_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 2), 0x718BCD58L);
		FF_2_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 25), 0x82154AEEL);
		FF_2_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 31), 0x7B54A41DL);
		FF_2_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 27), 0xC25A59B5L);

		// Pass 3
		FF_3_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 19), 0x9C30D539L);
		FF_3_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 9), 0x2AF26013L);
		FF_3_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 4), 0xC5D1B023L);
		FF_3_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 20), 0x286085F0L);
		FF_3_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 28), 0xCA417918L);
		FF_3_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 17), 0xB8DB38EFL);
		FF_3_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 8), 0x8E79DCB0L);
		FF_3_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 22), 0x603A180EL);

		FF_3_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 29), 0x6C9E0E8BL);
		FF_3_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 14), 0xB01E8A3EL);
		FF_3_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 25), 0xD71577C1L);
		FF_3_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 12), 0xBD314B27L);
		FF_3_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 24), 0x78AF2FDAL);
		FF_3_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 30), 0x55605C60L);
		FF_3_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 16), 0xE65525F3L);
		FF_3_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 26), 0xAA55AB94L);

		FF_3_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 31), 0x57489862L);
		FF_3_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 15), 0x63E81440L);
		FF_3_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 7), 0x55CA396AL);
		FF_3_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 3), 0x2AAB10B6L);
		FF_3_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 1), 0xB4CC5C34L);
		FF_3_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w), 0x1141E8CEL);
		FF_3_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 18), 0xA15486AFL);
		FF_3_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 27), 0x7C72E993L);

		FF_3_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 13), 0xB3EE1411L);
		FF_3_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 6), 0x636FBC2AL);
		FF_3_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 21), 0x2BA9C55DL);
		FF_3_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 10), 0x741831F6L);
		FF_3_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 23), 0xCE5C3E16L);
		FF_3_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 11), 0x9B87931EL);
		FF_3_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 5), 0xAFD6BA33L);
		FF_3_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 2), 0x6C24CF5CL);

		// Pass 4. executed only when PASS =4 or 5
		FF_4_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 24), 0x7A325381L);
		FF_4_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 4), 0x28958677L);
		FF_4_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w), 0x3B8F4898L);
		FF_4_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 14), 0x6B4BB9AFL);
		FF_4_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 2), 0xC4BFE81BL);
		FF_4_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 7), 0x66282193L);
		FF_4_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 28), 0x61D809CCL);
		FF_4_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 23), 0xFB21A991L);

		FF_4_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 26), 0x487CAC60L);
		FF_4_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 6), 0x5DEC8032L);
		FF_4_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 30), 0xEF845D5DL);
		FF_4_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 20), 0xE98575B1L);
		FF_4_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 18), 0xDC262302L);
		FF_4_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 25), 0xEB651B88L);
		FF_4_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 19), 0x23893E81L);
		FF_4_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 3), 0xD396ACC5L);

		FF_4_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 22), 0x0F6D6FF3L);
		FF_4_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 11), 0x83F44239L);
		FF_4_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 31), 0x2E0B4482L);
		FF_4_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 21), 0xA4842004L);
		FF_4_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 8), 0x69C8F04AL);
		FF_4_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 27), 0x9E1F9B5EL);
		FF_4_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 12), 0x21C66842L);
		FF_4_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 9), 0xF6E96C9AL);

		FF_4_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 1), 0x670C9C61L);
		FF_4_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 29), 0xABD388F0L);
		FF_4_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 5), 0x6A51A0D2L);
		FF_4_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 15), 0xD8542F68L);
		FF_4_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 17), 0x960FA728L);
		FF_4_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 10), 0xAB5133A3L);
		FF_4_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 16), 0x6EEF0B6CL);
		FF_4_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 13), 0x137A3BE4L);

		// Pass 5. executed only when PASS = 5
		FF_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 27), 0xBA3BF050L);
		FF_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 3), 0x7EFB2A98L);
		FF_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 21), 0xA1F1651DL);
		FF_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 26), 0x39AF0176L);
		FF_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 17), 0x66CA593EL);
		FF_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 11), 0x82430E88L);
		FF_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 20), 0x8CEE8619L);
		FF_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 29), 0x456F9FB4L);

		FF_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 19), 0x7D84A5C3L);
		FF_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w), 0x3B8B5EBEL);
		FF_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 12), 0xE06F75D8L);
		FF_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 7), 0x85C12073L);
		FF_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 13), 0x401A449FL);
		FF_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 8), 0x56C16AA6L);
		FF_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 31), 0x4ED3AA62L);
		FF_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 10), 0x363F7706L);

		FF_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 5), 0x1BFEDF72L);
		FF_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 9), 0x429B023DL);
		FF_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 14), 0x37D0D724L);
		FF_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 30), 0xD00A1248L);
		FF_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 18), 0xDB0FEAD3L);
		FF_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 6), 0x49F1C09BL);
		FF_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 28), 0x075372C9L);
		FF_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 24), 0x80991B7BL);

		FF_5(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 2), 0x25D479D8L);
		FF_5(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 23), 0xF6E8DEF7L);
		FF_5(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 16), 0xE3FE501AL);
		FF_5(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 22), 0xB6794C3BL);
		FF_5(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 4), 0x976CE0BDL);
		FF_5(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 1), 0x04C006BAL);
		FF_5(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 25), 0xC1A94FB6L);
		FF_5(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 15), 0x409F60C4L);
	}
	else throw EDCP_hash("Bad passCount="+to_string(passCount));

	CurrentHash[0] += t0;
	CurrentHash[1] += t1;
	CurrentHash[2] += t2;
	CurrentHash[3] += t3;
	CurrentHash[4] += t4;
	CurrentHash[5] += t5;
	CurrentHash[6] += t6;
	CurrentHash[7] += t7;

}


int DCPh_haval::getHashSize()
{
	return digestBits;
}


std::string DCPh_haval::getAlgorithm()
{
	string result = "haval-" + to_string(digestBits) + "-" + to_string(passCount);
	return result;
}


//https://md5calc.com/hash/haval128-3/a
bool DCPh_haval::selfTest()
{
	bool result = false;
	if (passCount == 3)
	{
		if (digestBits == 128)
		{
			const uint8_t Test1Out[16] = { 0x0c,0xd4,0x07,0x39,0x68,0x3e,0x15,0xf0,0x1c,0xa5,0xdb,0xce,0xef,0x40,0x59,0xf1 };
			uint8_t TestOut[16];
			init();
			updateStr(string("a"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else if (digestBits == 160)
		{
			const uint8_t Test1Out[20] = { 0x4d,0xa0,0x8f,0x51,0x4a,0x72,0x75,0xdb,0xc4,0xce,0xce,0x4a,0x34,0x73,0x85,0x98,
				0x39,0x83,0xa8,0x30 };
			uint8_t TestOut[20];
			init();
			updateStr(string("a"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else if (digestBits == 192)
		{
			const uint8_t Test1Out[24] = { 0xa7,0xb1,0x4c,0x9e,0xf3,0x09,0x23,0x19,0xb0,0xe7,0x5e,0x3b,0x20,0xb9,0x57,0xd1,
				0x80,0xbf,0x20,0x74,0x56,0x29,0xe8,0xde };
			uint8_t TestOut[24];
			init();
			updateStr(string("abc"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else if (digestBits == 224)
		{
			const uint8_t Test1Out[28] = { 0x5b,0x1a,0x62,0xb2,0xcc,0x62,0x83,0x49,0x38,0xb4,0x38,0x6f,0x78,0x6a,0xe6,0xb3,
				0xba,0x26,0x3a,0x0f,0xec,0x20,0x07,0xa6,0x03,0x38,0x82,0x09 };
			uint8_t TestOut[28];
			init();
			updateStr(string("abcdefg"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else if (digestBits == 256)
		{
			const uint8_t Test1Out[32] = { 0x91,0x85,0x0c,0x64,0x87,0xc9,0x82,0x9e,0x79,0x1f,0xc5,0xb5,0x8e,0x98,0xe3,0x72,
				0xf3,0x06,0x32,0x56,0xbb,0x7d,0x31,0x3a,0x93,0xf1,0xf8,0x3b,0x42,0x6a,0xed,0xcc };
			uint8_t TestOut[32];
			init();
			updateStr(string("HAVAL"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else throw EDCP_hash("Bad combination len/numRounds");
	}
	else if (passCount == 4)
	{
		if (digestBits == 128)
		{
			const uint8_t Test1Out[16] = { 0x5c,0xd0,0x7f,0x03,0x33,0x0c,0x3b,0x50,0x20,0xb2,0x9b,0xa7,0x59,0x11,0xe1,0x7d };
			uint8_t TestOut[16];
			init();
			updateStr(string("a"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else if (digestBits == 160)
		{
			const uint8_t Test1Out[20] = { 0xe0,0xa5,0xbe,0x29,0x62,0x73,0x32,0x03,0x4d,0x4d,0xd8,0xa9,0x10,0xa1,0xa0,0xe6,
				0xfe,0x04,0x08,0x4d };
			uint8_t TestOut[20];
			init();
			updateStr(string("a"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else if (digestBits == 192)
		{
			const uint8_t Test1Out[24] = { 0x0c,0x13,0x96,0xd7,0x77,0x26,0x89,0xc4,0x67,0x73,0xf3,0xda,0xac,0xa4,0xef,0xa9,
				0x82,0xad,0xbf,0xb2,0xf1,0x46,0x7e,0xea };
			uint8_t TestOut[24];
			init();
			updateStr(string("HAVAL"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else if (digestBits == 224)
		{
			const uint8_t Test1Out[28] = { 0xbe,0xbd,0x78,0x16,0xf0,0x9b,0xae,0xec,0xf8,0x90,0x3b,0x1b,0x9b,0xc6,0x72,0xd9,
				0xfa,0x42,0x8e,0x46,0x2b,0xa6,0x99,0xf8,0x14,0x84,0x15,0x29};
			uint8_t TestOut[28];
			init();
			updateStr(string("0123456789"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else if (digestBits == 256)
		{
			const uint8_t Test1Out[32] = { 0xe2,0x06,0x43,0xcf,0xa6,0x6f,0x5b,0xe2,0x14,0x5d,0x13,0xed,0x09,0xc2,0xff,0x62,
				0x2b,0x3f,0x0d,0xa4,0x26,0xa6,0x93,0xfa,0x3b,0x3e,0x52,0x9c,0xa8,0x9e,0x0d,0x3c };
			uint8_t TestOut[32];
			init();
			updateStr(string("HAVAL"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else throw EDCP_hash("Bad combination len/numRounds");
	}
	else if (passCount == 5)
	{
		if (digestBits == 128)
		{
			const uint8_t Test1Out[16] = { 0xf2,0x3f,0xbe,0x70,0x4b,0xe8,0x49,0x4b,0xfa,0x7a,0x7f,0xb4,0xf8,0xab,0x09,0xe5 };
			uint8_t TestOut[16];
			init();
			updateStr(string("a"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else if (digestBits == 160)
		{
			const uint8_t Test1Out[20] = { 0xf5,0x14,0x7d,0xf7,0xab,0xc5,0xe3,0xc8,0x1b,0x03,0x12,0x68,0x92,0x7c,0x2b,0x57,
				0x61,0xb5,0xa2,0xb5 };
			uint8_t TestOut[20];
			init();
			updateStr(string("a"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else if (digestBits == 192)
		{
			const uint8_t Test1Out[24] = { 0x79,0x4a,0x89,0x6d,0x17,0x80,0xb7,0x6e,0x27,0x67,0xcc,0x40,0x11,0xba,0xd8,0x88,
				0x5d,0x5c,0xe6,0xbd,0x83,0x5a,0x71,0xb8 };
			uint8_t TestOut[24];
			init();
			updateStr(string("HAVAL"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else if (digestBits == 224)
		{
			const uint8_t Test1Out[28] = { 0x59,0x83,0x6d,0x19,0x26,0x91,0x35,0xbc,0x81,0x5f,0x37,0xb2,0xae,0xb1,0x5f,0x89,
				0x4b,0x54,0x35,0xf2,0xc6,0x98,0xd5,0x77,0x16,0x76,0x0f,0x2b };
			uint8_t TestOut[28];
			init();
			updateStr(string("0123456789"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
		}
		else if (digestBits == 256)
		{
			const uint8_t Test1Out[32] = { 0xc9,0xc7,0xd8,0xaf,0xa1,0x59,0xfd,0x9e,0x96,0x5c,0xb8,0x3f,0xf5,0xee,0x6f,0x58,
				0xae,0xda,0x35,0x2c,0x0e,0xff,0x00,0x55,0x48,0x15,0x3a,0x61,0x55,0x1c,0x38,0xee };
			const uint8_t Test2Out[32] = { 0xb4,0x5c,0xb6,0xe6,0x2f,0x2b,0x13,0x20,0xe4,0xf8,0xf1,0xb0,0xb2,0x73,0xd4,0x5a,
				0xdd,0x47,0xc3,0x21,0xfd,0x23,0x99,0x9d,0xcf,0x40,0x3a,0xc3,0x76,0x36,0xd9,0x63 };
			uint8_t TestOut[32];
			init();
			updateStr(string("abcdefghijklmnopqrstuvwxyz"));
			final(TestOut);
			result = memcmp(TestOut, Test1Out, sizeof(Test1Out)) == 0;
			init();
			updateStr(string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
			final(TestOut);
			result = memcmp(TestOut, Test2Out, sizeof(Test2Out)) == 0 && result;
		}
		else throw EDCP_hash("Bad combination len/nuRounds");
	}
	else throw EDCP_hash("Invalid pass count " + to_string(passCount));
	return result;
}

void DCPh_haval::init()
{
	burn();
	CurrentHash[0] = 0x243f6a88;
	CurrentHash[1] = 0x85a308d3;
	CurrentHash[2] = 0x13198a2e;
	CurrentHash[3] = 0x3707344;
	CurrentHash[4] = 0xa4093822;
	CurrentHash[5] = 0x299f31d0;
	CurrentHash[6] = 0x82efa98;
	CurrentHash[7] = 0xec4e6c89;
	fInitialized = true;
}

void DCPh_haval::burn()
{
	count[0] = 0; count[1] = 0;
	index = 0;
	memset(HashBuffer, 0, sizeof(HashBuffer));
	memset(CurrentHash, 0, sizeof(CurrentHash));
	fInitialized = false;
}

/*
* translate every four characters into a word.
* assume the number of characters is a multiple of four.
*/
#define ch2uint(string, word, slen) {      \
  uint8_t *sp = string;              \
  uint32_t    *wp = (uint32_t *)word;                \
  while (sp < (string) + (slen)) {         \
    *wp++ =  (uint32_t)*sp            |  \
            ((uint32_t)*(sp+1) <<  8) |  \
            ((uint32_t)*(sp+2) << 16) |  \
            ((uint32_t)*(sp+3) << 24);   \
    sp += 4;                               \
  }                                        \
}

/* translate each word into four characters */
#define uint2ch(word, string, wlen) {              \
  uint32_t    *wp = word;                        \
  uint8_t *sp = string;                      \
  while (wp < (word) + (wlen)) {                   \
    *(sp++) = (uint8_t)( *wp        & 0xFF); \
    *(sp++) = (uint8_t)((*wp >>  8) & 0xFF); \
    *(sp++) = (uint8_t)((*wp >> 16) & 0xFF); \
    *(sp++) = (uint8_t)((*wp >> 24) & 0xFF); \
    wp++;                                          \
  }                                                \
}

void DCPh_haval::update(const unsigned char *buffer, uint32_t size)
{
	unsigned int i,
		rmd_len,
		fill_len;

	// calculate the number of bytes in the remainder
	rmd_len = (unsigned int)((count[0] >> 3) & 0x7F);
	fill_len = 128 - rmd_len;

	// update the number of bits
	if ((count[0] += size << 3) < (size << 3)) {
		count[1]++;
	}
	count[1] += size >> 29;

	if (little_endian() == 1)
	{
		// hash as many blocks as possible
		if (rmd_len + size >= 128) {
			memcpy(HashBuffer + rmd_len, buffer, fill_len);
			compress();
			for (i = fill_len; i + 127 < size; i += 128) {
				memcpy(HashBuffer, buffer + i, 128);
				compress();
			}
			rmd_len = 0;
		}
		else {
			i = 0;
		}
		memcpy(HashBuffer + rmd_len, buffer + i, size - i);
	}
	else
	{
		// hash as many blocks as possible
		if (rmd_len + size >= 128) {
			memcpy(&Remainder[rmd_len], buffer, fill_len);
			ch2uint(Remainder, HashBuffer, 128);
			compress();
			for (i = fill_len; i + 127 < size; i += 128) {
				memcpy(Remainder, buffer + i, 128);
				ch2uint(Remainder, HashBuffer, 128);
				compress();
			}
			rmd_len = 0;
		}
		else {
			i = 0;
		}
		// save the remaining input chars
		memcpy(&Remainder[rmd_len], buffer + i, size - i);
	}
}

// tailor the last output
void DCPh_haval::tailor()
{
	uint32_t temp;

	if (digestBits == 128)
	{
		temp = (CurrentHash[7] & 0x000000FFL) |
			(CurrentHash[6] & 0xFF000000L) |
			(CurrentHash[5] & 0x00FF0000L) |
			(CurrentHash[4] & 0x0000FF00L);
		CurrentHash[0] += rotate_right(temp, 8);

		temp = (CurrentHash[7] & 0x0000FF00L) |
			(CurrentHash[6] & 0x000000FFL) |
			(CurrentHash[5] & 0xFF000000L) |
			(CurrentHash[4] & 0x00FF0000L);
		CurrentHash[1] += rotate_right(temp, 16);

		temp = (CurrentHash[7] & 0x00FF0000L) |
			(CurrentHash[6] & 0x0000FF00L) |
			(CurrentHash[5] & 0x000000FFL) |
			(CurrentHash[4] & 0xFF000000L);
		CurrentHash[2] += rotate_right(temp, 24);

		temp = (CurrentHash[7] & 0xFF000000L) |
			(CurrentHash[6] & 0x00FF0000L) |
			(CurrentHash[5] & 0x0000FF00L) |
			(CurrentHash[4] & 0x000000FFL);
		CurrentHash[3] += temp;
	}
	if (digestBits == 160)
	{
		temp = (CurrentHash[7] & (uint32_t)0x3F) |
			(CurrentHash[6] & ((uint32_t)0x7F << 25)) |
			(CurrentHash[5] & ((uint32_t)0x3F << 19));
		CurrentHash[0] += rotate_right(temp, 19);

		temp = (CurrentHash[7] & ((uint32_t)0x3F << 6)) |
			(CurrentHash[6] & (uint32_t)0x3F) |
			(CurrentHash[5] & ((uint32_t)0x7F << 25));
		CurrentHash[1] += rotate_right(temp, 25);

		temp = (CurrentHash[7] & ((uint32_t)0x7F << 12)) |
			(CurrentHash[6] & ((uint32_t)0x3F << 6)) |
			(CurrentHash[5] & (uint32_t)0x3F);
		CurrentHash[2] += temp;

		temp = (CurrentHash[7] & ((uint32_t)0x3F << 19)) |
			(CurrentHash[6] & ((uint32_t)0x7F << 12)) |
			(CurrentHash[5] & ((uint32_t)0x3F << 6));
		CurrentHash[3] += temp >> 6;

		temp = (CurrentHash[7] & ((uint32_t)0x7F << 25)) |
			(CurrentHash[6] & ((uint32_t)0x3F << 19)) |
			(CurrentHash[5] & ((uint32_t)0x7F << 12));
		CurrentHash[4] += temp >> 12;
	}
	if (digestBits == 192)
	{
		temp = (CurrentHash[7] & (uint32_t)0x1F) |
			(CurrentHash[6] & ((uint32_t)0x3F << 26));
		CurrentHash[0] += rotate_right(temp, 26);

		temp = (CurrentHash[7] & ((uint32_t)0x1F << 5)) |
			(CurrentHash[6] & (uint32_t)0x1F);
		CurrentHash[1] += temp;

		temp = (CurrentHash[7] & ((uint32_t)0x3F << 10)) |
			(CurrentHash[6] & ((uint32_t)0x1F << 5));
		CurrentHash[2] += temp >> 5;

		temp = (CurrentHash[7] & ((uint32_t)0x1F << 16)) |
			(CurrentHash[6] & ((uint32_t)0x3F << 10));
		CurrentHash[3] += temp >> 10;

		temp = (CurrentHash[7] & ((uint32_t)0x1F << 21)) |
			(CurrentHash[6] & ((uint32_t)0x1F << 16));
		CurrentHash[4] += temp >> 16;

		temp = (CurrentHash[7] & ((uint32_t)0x3F << 26)) |
			(CurrentHash[6] & ((uint32_t)0x1F << 21));
		CurrentHash[5] += temp >> 21;
	}
	if (digestBits == 224)
	{
		CurrentHash[0] += (CurrentHash[7] >> 27) & 0x1F;
		CurrentHash[1] += (CurrentHash[7] >> 22) & 0x1F;
		CurrentHash[2] += (CurrentHash[7] >> 18) & 0x0F;
		CurrentHash[3] += (CurrentHash[7] >> 13) & 0x1F;
		CurrentHash[4] += (CurrentHash[7] >> 9) & 0x0F;
		CurrentHash[5] += (CurrentHash[7] >> 4) & 0x1F;
		CurrentHash[6] += CurrentHash[7] & 0x0F;
	}
}

static unsigned char padding[128] = {        // constants for padding
	0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void DCPh_haval::final(uint8_t *digest)
{
	uint32_t temp;
	if (!fInitialized)
		throw EDCP_hash("Hash not initialized");

	unsigned char tail[10];
	unsigned int  rmd_len, pad_len;

	/*
	* save the version number, the number of passes, the fingerprint
	* length and the number of bits in the unpadded message.
	*/
	tail[0] = (unsigned char)(((digestBits & 0x3) << 6) |
		((passCount & 0x7) << 3) |
		(HAVAL_VERSION & 0x7));
	tail[1] = (unsigned char)((digestBits >> 2) & 0xFF);
	uint2ch(count, &tail[2], 2);

	// pad out to 118 mod 128
	rmd_len = (unsigned int)((count[0] >> 3) & 0x7f);
	pad_len = (rmd_len < 118) ? (118 - rmd_len) : (246 - rmd_len);
	update(padding, pad_len);

	/*
	* append the version number, the number of passes,
	* the fingerprint length and the number of bits
	*/
	update(tail, 10);

	// tailor the last output
	tailor();

	// translate and save the final fingerprint
	uint2ch(CurrentHash, digest, digestBits >> 5);

	burn();
}
