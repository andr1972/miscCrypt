/*
*  haval.c:  specifies the routines in the HAVAL (V.1) hashing library.
*
*  Copyright (c) 2003 Calyptix Security Corporation
*  All rights reserved.
*
*  This code is derived from software contributed to Calyptix Security
*  Corporation by Yuliang Zheng.
*
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted provided that the following conditions
*  are met:
*  1. Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*  2. Redistributions in binary form must reproduce the above
*     copyright notice, this list of conditions and the following
*     disclaimer in the documentation and/or other materials provided
*     with the distribution.
*  3. Neither the name of Calyptix Security Corporation nor the
*     names of its contributors may be used to endorse or promote
*     products derived from this software without specific prior
*     written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
* FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
* COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
* BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
* ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* -------------------------------------------------------------------
*
*      HAVAL is a one-way hashing algorithm with the following
*      collision-resistant property:
*             It is computationally infeasible to find two or more
*             messages that are hashed into the same fingerprint.
*
*  Reference:
*       Y. Zheng, J. Pieprzyk and J. Seberry:
*       ``HAVAL --- a one-way hashing algorithm with variable
*       length of output'', Advances in Cryptology --- AUSCRYPT'92,
*       Lecture Notes in Computer Science,  Vol.718, pp.83-104,
*       Springer-Verlag, 1993.
*
*  Descriptions:
*      -  haval_string:      hash a string
*      -  haval_file:        hash a file
*      -  haval_stdin:       filter -- hash input from the stdin device
*      -  haval_hash:        hash a string of specified length
*                            (Haval_hash is used in conjunction with
*                             haval_start & haval_end.)
*      -  haval_hash_block:  hash a 32-word block
*      -  haval_start:       initialization
*      -  haval_end:         finalization
*
*  Authors:    Yuliang Zheng and Lawrence Teo
*              Calyptix Security Corporation
*              P.O. Box 561508, Charlotte, NC 28213, USA
*              Email: info@calyptix.com
*              URL:   http://www.calyptix.com/
*              Voice: +1 704 806 8635
*
*  For a list of changes, see the ChangeLog file.
*/
#pragma once
#include "DCP_hash.h"
#include <stdint.h>

namespace dcpcrypt {

class DCPh_haval :public DCP_hash
{
protected:
	uint32_t count[2]; /* number of bits in a message */
	uint32_t index;
	uint32_t CurrentHash[8];
	uint8_t HashBuffer[128];
	uint8_t Remainder[32 * 4];         /* unhashed chars (No.<128) */
	void compress();
	void tailor();
	int digestBits;
	int passCount;
public:
	DCPh_haval(int digestBits = 256, int passCount = 5);
	~DCPh_haval();
	virtual DCPenum getId() { return DCPenum::h_haval; };
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