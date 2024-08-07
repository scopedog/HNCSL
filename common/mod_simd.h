/******************************************************************************
Copyright (c) 2024, Hiroshi Nishida and ASUSA Corporation
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
******************************************************************************/

#ifndef _MOD_SIMD_H_
#define _MOD_SIMD_H_

#if defined(__SSSE3__) || defined(__AVX2__)
#include <immintrin.h>
#elif defined(_arm64_)
#include <arm_neon.h>
#endif

// Definitions 
#if defined(__SSSE3__) || defined(__AVX2__)
typedef __m128i		v128_t;
#elif defined(_arm64_) // NEON
typedef uint8x16_t	v128_t;
#endif

// Inline functions
#if defined(__SSSE3__) || defined(__AVX2__) || defined(_arm64_)
// Show each byte of v128_t
static inline void
mm_print128_8(const char *str, v128_t var)
{
	uint8_t val[16];

	memcpy(val, &var, sizeof(val));

	printf("%s%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
	       "%02x %02x %02x %02x %02x\n",  str,
#if 1   // Left to right
		val[15], val[14], val[13], val[12], val[11], val[10], val[9],
		val[8], val[7], val[6], val[5], val[4], val[3], val[2],
		val[1], val[0]);
#else   // Right to left
		val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
		val[8], val[9], val[10], val[11], val[12], val[13],
		val[14], val[15]);
#endif
}
#endif

#if defined(__AVX2__)
// Show each byte of __m256i
static inline void
mm_print256_8(const char *str, __m256i var)
{
	uint8_t val[32];
	size_t	len = strlen(str);

	memcpy(val, &var, sizeof(val));

	printf("%s%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
	       "%02x %02x %02x %02x %02x\n",  str,
		val[15], val[14], val[13], val[12], val[11], val[10], val[9],
		val[8], val[7], val[6], val[5], val[4], val[3], val[2],
		val[1], val[0]);
	for (; len; len--) {
		putchar(' ');
	}
	printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
	       "%02x %02x %02x %02x %02x\n",
		val[31], val[30], val[29], val[28], val[27], val[26], val[25],
		val[24], val[23], val[22], val[21], val[20], val[19], val[18],
		val[17], val[16]);
}
#endif

#endif // _MOD_SIMD_H_
