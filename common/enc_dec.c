/******************************************************************************
Copyright (c) 2023, Hiroshi Nishida and ASUSA Corporation
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

/*
	CAUTION!
	Mod16EncSIMDRemNoPad(), Mod16DecSIMDRemNoPad() 
	Mod32EncSIMDRemNoPad(), Mod32DecSIMDRemNoPad()
	assume sizeof(MOD_T) * HNC_RANK <= 16 (128bit).
	Therefore, HNC_RANK must be <= 8 for Mod16 and <= 4 for Mod32.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if defined(_amd64_) || defined(_x86_64_)
#include <immintrin.h>
#elif defined(_arm64_)
#include <arm_neon.h>
#endif
#include "common.h"
#include "enc_dec.h"
#include "mod.h"
#include "mod_simd.h"
#include "mod_mtrx.h"
#include "log.h"
#include "util.h"
#include "SFMT/SFMT.h"


/******************************************************************************
	Functions
******************************************************************************/

// Allocate HNC data
HNCdatS *
AllocHNCdat(void)
{
	int	h, i, err = 0;
	size_t	size;
	MOD_T	**key_mtrx_enc, **key_mtrx_dec;
	HNCdatS	*hnc_dat = NULL;

	// Allocate hnc_dat
	size = sizeof(HNCdatS) % 32;
	size = sizeof(HNCdatS) + 32 - size;
	if ((hnc_dat = aligned_alloc(32, size)) == NULL) {
		Log("Error: aligned_alloc hnc_dat: %s", strerror(errno));
		err = errno;
		goto END;
	}

	// Allocate init_prev_c_prime
	if ((hnc_dat->init_prev_c_prime = (uint8_t *)
			aligned_alloc(32, 32 * HNC_RANK)) == NULL) {
		Log("Error: aligned_alloc hnc_dat->init_prev_c_prime: %s",
			strerror(errno));
		err = errno;
		goto END;
	}

	// Allocate key matrices
	for (h = 0; h < NUM_MTRX_KEYS; h++) {
		key_mtrx_enc = hnc_dat->key_mtrx_enc[h];
		key_mtrx_dec = hnc_dat->key_mtrx_dec[h];
		for (i = 0; i < HNC_RANK; i++) {
			if ((key_mtrx_enc[i] =
				malloc(sizeof(MOD_T) * HNC_RANK)) == NULL) {
				Log("Error: %s: aligned_alloc key_mtrx_enc: %s",
					__func__, strerror(errno));
				err = errno;
				goto END;
			}
			if ((key_mtrx_dec[i] =
				malloc(sizeof(MOD_T) * HNC_RANK)) == NULL) {
				Log("Error: %s: aligned_alloc key_mtrx_dec: %s",
					__func__, strerror(errno));
				err = errno;
				goto END;
			}
		}
	}

	// Initialize random # generator
	{
		struct timespec	ts;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		sfmt_init_gen_rand(&hnc_dat->sfmt, ts.tv_sec ^ ts.tv_nsec);
	}

	// Initialize hnc_dat
	InitHNCdat(hnc_dat);

END:	// Finialize
	if (err) {
		FreeHNCdat(hnc_dat);
		return NULL;
	}
	else {
		return hnc_dat;
	}
}

// Free HNC data
void
FreeHNCdat(HNCdatS *hnc_dat)
{
	int	h, i;
	MOD_T	**key_mtrx_enc, **key_mtrx_dec;

	if (hnc_dat == NULL) {
		return;
	}

	// Free init_prev_c_prime
	free(hnc_dat->init_prev_c_prime);

	// Free coef
	for (h = 0; h < NUM_MTRX_KEYS; h++) {
		key_mtrx_enc = hnc_dat->key_mtrx_enc[h];
		key_mtrx_dec = hnc_dat->key_mtrx_dec[h];
		for (i = 0; i < HNC_RANK; i++) {
			if (key_mtrx_enc[i] == NULL) {
				break;
			}
			free(key_mtrx_enc[i]);

			if (key_mtrx_dec[i] == NULL) {
				break;
			}
			free(key_mtrx_dec[i]);
		}
	}

	// Free hnc_dat
	free(hnc_dat);
}

// Initialize HNC data
int
InitHNCdat(HNCdatS *hnc_dat)
{
	hnc_dat->inited = true;
	hnc_dat->key_idx = 0;

	return 0;
}

// Initialize prev_c_prime with init_prev_c_prime
void
InitHNCxorKey(HNCdatS *hnc_dat)
{
	uint64_t	i, j;
	uint8_t		*key_beta;
	uint8_t		*init_prev_c_prime = hnc_dat->init_prev_c_prime;
	VEC_T		*key_beta_v;
	VEC_T		*prev_c_prime = hnc_dat->prev_c_prime;

	// Load key_beta
	for (i = 0; i < NUM_BETA_KEYS; i++) {
		key_beta = hnc_dat->key_beta[i];
		key_beta_v = hnc_dat->key_beta_v[i];

#if defined(__AVX2__)
		for (j = 0; j < HNC_RANK; j++) {
			key_beta_v[j] = _mm256_loadu_si256((__m256i *)key_beta);
			key_beta += 32;
		}
#elif defined(_arm64_)
		for (j = 0; j < HNC_RANK * 2; j++) {
			key_beta_v[j] = vld1q_u8(key_beta);
			key_beta += 16;
		}
#endif
	}

	key_beta_v = hnc_dat->key_beta_v[0];

#if defined(__AVX2__)
	// Copy key_beta[0][0] to key_beta_v_0
	hnc_dat->key_beta_v_0 = key_beta_v[0];

	// Load prev_c_prime from init_prev_c_prime
	for (i = 0; i < HNC_RANK; i++) {
		// prev_c_prime must be aligned
		prev_c_prime[i] =
			_mm256_load_si256((__m256i *)init_prev_c_prime);
		init_prev_c_prime += 32;
	}

	// Copy prev_c_prime[0] to prev_c_prime_0
	hnc_dat->prev_c_prime_0 = prev_c_prime[0];

#elif defined(_arm64_)
	// Copy key_beta[0][0] to key_beta_v_*
	hnc_dat->key_beta_v_0 = key_beta_v[0];
	hnc_dat->key_beta_v_1 = key_beta_v[1];

	// Load prev_c_prime from init_prev_c_prime
	for (i = 0; i < HNC_RANK * 2; i++) {
		prev_c_prime[i] = vld1q_u8(init_prev_c_prime);
		init_prev_c_prime += 16;
	}

	// Copy prev_c_prime[0, 1] to prev_c_prime_0_*
	hnc_dat->prev_c_prime_0 = prev_c_prime[0];
	hnc_dat->prev_c_prime_1 = prev_c_prime[1];
#endif
}

// Generate random init_prev_c_prime 
void
GenHNCinitXorKey(HNCdatS *hnc_dat)
{
	uint64_t	i, j;
	uint64_t	*init_prev_c_prime =
				(uint64_t *)hnc_dat->init_prev_c_prime;
	uint64_t	*key_beta;
	sfmt_t		*sfmt = &hnc_dat->sfmt;

	// Input random numbers to key_beta
	for (i = 0; i < NUM_BETA_KEYS; i++) {
		key_beta = (uint64_t *)hnc_dat->key_beta[i];
		for (j = 0; j < SIMD_ENCRYPT_SIZE / sizeof(uint64_t); j++) {
			*key_beta = sfmt_genrand_uint64(sfmt);
			key_beta++;
		}
	}

	// Input random numbers to init_prev_c_prime
	for (i = 0; i < SIMD_ENCRYPT_SIZE / sizeof(uint64_t); i++) {
		*init_prev_c_prime = sfmt_genrand_uint64(sfmt);
		init_prev_c_prime++;
	}
}

// Generate random coef 
void
GenHNCcoef(HNCdatS *hnc_dat)
{
	int	h, i, j;
	MOD_T	*key_mtrx_enc;
	sfmt_t	*sfmt = &hnc_dat->sfmt;

	// Generate coef for SIMD
	for (h = 0; h < NUM_MTRX_KEYS; h++) {
NEW_COEF:
		// Generate random coefs and check matrix is invertible
		for (i = 0; i < HNC_RANK; i++) {
			key_mtrx_enc = hnc_dat->key_mtrx_enc[h][i];
			for (j = 0; j < HNC_RANK; j++) {
				key_mtrx_enc[j] = (MOD_T)
					(sfmt_genrand_uint64(sfmt) & MOD_T_MAX);
//printf("%d,", key_mtrx_enc[j]);
			}
//putchar('\n');
		}

#if defined(_MOD16_) // 16bit
		// Invert key_mtrx_enc
		if (Mod16InvMtrx(hnc_dat->key_mtrx_enc[h],
				hnc_dat->key_mtrx_dec[h], HNC_RANK) == -1) {
			// Inverse matrix does not exist
			//Log("Info: MOD16InvMtrx failed. Will try new coef.");
			goto NEW_COEF;
		}

/*
		// Debug
		uint16_t	*C[HNC_RANK];
		for (i = 0; i < HNC_RANK; i++) {
			C[i] = malloc(sizeof(uint16_t) * HNC_RANK);
		}

		MOD16MtrxByMtrx(hnc_dat->key_mtrx_enc[h], hnc_dat->key_mtrx_dec[h], C, HNC_RANK);
		putchar('\n');
		MOD16ShowMtrx(C, HNC_RANK);
		for (i = 0; i < HNC_RANK; i++) {
			free(C[i]);
		}
*/
#elif defined(_MOD32_) // 32bit
		// Invert key_mtrx_enc
		if (Mod32InvMtrx(hnc_dat->key_mtrx_enc[h],
				hnc_dat->key_mtrx_dec[h], HNC_RANK) == -1) {
			// Inverse matrix does not exist
			goto NEW_COEF;
		}

/*
		// Debug
		uint32_t	*C[HNC_RANK];
		for (i = 0; i < HNC_RANK; i++) {
			C[i] = malloc(sizeof(uint32_t) * HNC_RANK);
		}

		MOD32MtrxByMtrx(hnc_dat->key_mtrx_enc[h], hnc_dat->key_mtrx_dec[h], C, HNC_RANK);
		putchar('\n');
		MOD32ShowMtrx(C, HNC_RANK);
		for (i = 0; i < HNC_RANK; i++) {
			free(C[i]);
		}
*/
#endif // _MOD*_
	}
}

// Set some parameters in HNCdat for encoding/decoding
int
SetHNCdatCod(HNCdatS *hnc_dat)
{
	uint64_t	h, i, j;
	MOD_T		tb_enc_tmp[NUM_MTRX_KEYS], tb_dec_tmp[NUM_MTRX_KEYS];
	MOD_T		*(*key_mtrx_enc)[HNC_RANK], *(*key_mtrx_dec)[HNC_RANK];
#if defined(__AVX2__)
	VEC_T		*tb_enc, *tb_dec;
#elif defined(_arm64_)
#if defined(_MOD16_)
	uint16x8_t	*tb_enc, *tb_dec;
#elif defined(_MOD32_)
	uint32x4_t	*tb_enc, *tb_dec;
#endif
#endif

	// Load xor keys
	InitHNCxorKey(hnc_dat);

	// Set vector tables for SIMD
	key_mtrx_enc = hnc_dat->key_mtrx_enc;
	key_mtrx_dec = hnc_dat->key_mtrx_dec;
/*
	puts("Enc:");
	for (h = 0; h < NUM_MTRX_KEYS; h++) {
		for (i = 0; i < HNC_RANK; i++) {
			for (j = 0; j < HNC_RANK; j++) {
				printf("%04x", key_mtrx_enc[h][i][j]);
			}
		}
	}
	putchar('\n');
*/
/*
	puts("Dec:");
	for (h = 0; h < NUM_MTRX_KEYS; h++) {
		for (i = 0; i < HNC_RANK; i++) {
			for (j = 0; j < HNC_RANK; j++) {
				printf("%04x", key_mtrx_dec[h][i][j]);
			}
		}
	}
	putchar('\n');
*/
	tb_enc = hnc_dat->tb_enc;
	tb_dec = hnc_dat->tb_dec;
	for (i = 0; i < HNC_RANK; i++) {
		for (j = 0; j < HNC_RANK; j++) {
			for (h = 0; h < NUM_MTRX_KEYS; h++) {
				tb_enc_tmp[h] = key_mtrx_enc[h][j][i];
				tb_dec_tmp[h] = key_mtrx_dec[h][j][i];
			}
#if defined(__AVX2__)
			*tb_enc = _mm256_loadu_si256((__m256i *)tb_enc_tmp);
			tb_enc++;
			*tb_dec = _mm256_loadu_si256((__m256i *)tb_dec_tmp);
			tb_dec++;
#elif defined(_arm64_)
#if defined(_MOD16_)
			*tb_enc = vld1q_u16(tb_enc_tmp); // Load first 16bytes
			tb_enc++;
			*tb_enc = vld1q_u16(tb_enc_tmp + 8); // Next 16bytes
			tb_enc++;
			*tb_dec = vld1q_u16(tb_dec_tmp); // Load first 16bytes
			tb_dec++;
			*tb_dec = vld1q_u16(tb_dec_tmp + 8); // Next 16bytes
			tb_dec++;
#elif defined(_MOD32_)
			*tb_enc = vld1q_u32(tb_enc_tmp); // Load first 16bytes
			tb_enc++;
			*tb_enc = vld1q_u32(tb_enc_tmp + 4); // Next 16bytes
			tb_enc++;
			*tb_dec = vld1q_u32(tb_dec_tmp); // Load first 16bytes
			tb_dec++;
			*tb_dec = vld1q_u32(tb_dec_tmp + 4); // Next 16bytes
			tb_dec++;
#endif
#endif
		}
	}

#if 0	// Debug
	puts("Enc:");
	for (i = 0; i < HNC_RANK * HNC_RANK; i++) {
		mm_print256_8("", tb_enc[i]);
	}
	putchar('\n');

	puts("Dec:");
	for (i = 0; i < HNC_RANK * HNC_RANK; i++) {
		mm_print256_8("", tb_dec[i]);
	}
	putchar('\n');
#endif

	// Reset inited
	hnc_dat->inited = true;

	// Reset key_idx
	hnc_dat->key_idx = 0;

	return 0;
}

// Reset some parameters for encoding/decoding
void
ResetHNCdatCod(HNCdatS *hnc_dat)
{
	// Reset XOR key
	InitHNCxorKey(hnc_dat);

	// Reset key_idx
	hnc_dat->key_idx = 0;

	// Reset key_idx
	hnc_dat->inited = true;
}

// Generate random keys (init_prev_c_prime and coef)
int
GenHNCkey(HNCdatS *hnc_dat)
{
	// Generate random init_prev_c_prime
	GenHNCinitXorKey(hnc_dat);

	// Generate random coef
	GenHNCcoef(hnc_dat);

	// Set other parms of hnc_dat
	return SetHNCdatCod(hnc_dat);
}

//#define _NO_SAMPLE_KEY	// Define if you don't use sample key

#ifndef _NO_SAMPLE_KEY
#include "sample-key.h"	

// Set sample keys from sample-key.h
void
SetSampleHNCkey(HNCdatS *hnc_dat)
{
	int64_t	i, j;

	// Copy key_beta
	memcpy(hnc_dat->key_beta, _key_beta, NUM_BETA_KEYS * SIMD_ENCRYPT_SIZE);

	// Copy init_prev_c_prime
	memcpy(hnc_dat->init_prev_c_prime, _init_prev_c_prime,
		SIMD_ENCRYPT_SIZE);

	// Copy key_mtrx_enc and key_mtrx_dec
	for (i = 0; i < (int64_t)NUM_MTRX_KEYS; i++) {
		for (j = 0; j < (int64_t)HNC_RANK; j++) {
			memcpy(hnc_dat->key_mtrx_enc[i][j], _key_mtrx_enc[i][j],
					sizeof(MOD_T) * HNC_RANK);
			memcpy(hnc_dat->key_mtrx_dec[i][j], _key_mtrx_dec[i][j],
					sizeof(MOD_T) * HNC_RANK);
		}
	}

	// Create tables
	SetHNCdatCod(hnc_dat);
}
#endif

// Show keys
void
ShowHNCkey(HNCdatS *hnc_dat)
{
	uint8_t	*key_beta;
	uint8_t	*init_prev_c_prime = hnc_dat->init_prev_c_prime;
	int64_t	i, j, k;
	MOD_T	*coef;

	// Show key_beta
	fputs("uint8_t\t_key_beta[NUM_BETA_KEYS][SIMD_ENCRYPT_SIZE] = {",
		stdout);
	for (i = 0; i < (int64_t)NUM_BETA_KEYS; i++) {
		key_beta = hnc_dat->key_beta[i];
		putchar('{');
		for (j = 0; j < (int64_t)SIMD_ENCRYPT_SIZE; j++) {
			printf("0x%02x", key_beta[j]);
			if (j != (int64_t)SIMD_ENCRYPT_SIZE - 1) {
				fputs(", ", stdout);
			}
		}
		fputs((i == (int64_t)NUM_BETA_KEYS - 1) ? "}" : "}, ", stdout);
	}
	puts("};");

	// Show init_prev_c_prime
	fputs("uint8_t\t_init_prev_c_prime[HNC_RANK * 32] = {", stdout);
	for (i = 0; i < (int64_t)SIMD_ENCRYPT_SIZE - 1; i++) {
		printf("0x%02x, ", init_prev_c_prime[i]);
	}
	printf("0x%02x};\n", init_prev_c_prime[i]);

	// Show key_mtrx_enc
#if defined(_MOD16_)
	fputs("static uint16_t\t_key_mtrx_enc[NUM_MTRX_KEYS][HNC_RANK][HNC_RANK] = {",
		stdout);
#elif defined(_MOD32_)
	fputs("static uint32_t\t_key_mtrx_enc[NUM_MTRX_KEYS][HNC_RANK][HNC_RANK] = {",
		stdout);
#endif
	for (i = 0; i < (int64_t)NUM_MTRX_KEYS; i++) {
		putchar('{');
		for (j = 0; j < (int64_t)HNC_RANK; j++) {
			coef = hnc_dat->key_mtrx_enc[i][j];
			putchar('{');
			for (k = 0; k < (int64_t)HNC_RANK; k++) {
#if defined(_MOD16_)
				printf("0x%04x", coef[k]);
#elif defined(_MOD32_)
				printf("0x%08x", coef[k]);
#endif
				if (k != (int64_t)HNC_RANK - 1) {
					fputs(", ", stdout);
				}
			}
			fputs((j == (int64_t)HNC_RANK - 1) ? "}" : "}, ",
				stdout);
		}
		fputs((i == (int64_t)NUM_MTRX_KEYS - 1) ? "}" : "}, ", stdout);
	}
	puts("};");

	// Show key_mtrx_dec
#if defined(_MOD16_)
	fputs("static uint16_t\t_key_mtrx_dec[NUM_MTRX_KEYS][HNC_RANK][HNC_RANK] = {",
		stdout);
#elif defined(_MOD32_)
	fputs("static uint32_t\t_key_mtrx_dec[NUM_MTRX_KEYS][HNC_RANK][HNC_RANK] = {",
		stdout);
#endif
	for (i = 0; i < (int64_t)NUM_MTRX_KEYS; i++) {
		putchar('{');
		for (j = 0; j < (int64_t)HNC_RANK; j++) {
			coef = hnc_dat->key_mtrx_dec[i][j];
			putchar('{');
			for (k = 0; k < (int64_t)HNC_RANK; k++) {
#if defined(_MOD16_)
				printf("0x%04x", coef[k]);
#elif defined(_MOD32_)
				printf("0x%08x", coef[k]);
#endif
				if (k != (int64_t)HNC_RANK - 1) {
					fputs(", ", stdout);
				}
			}
			fputs((j == (int64_t)HNC_RANK - 1) ? "}" : "}, ",
				stdout);
		}
		fputs((i == (int64_t)NUM_MTRX_KEYS - 1) ? "}" : "}, ", stdout);
	}
	puts("};");
}

#if defined(_MOD16_)
/****************************************************************************
	16bit encryption and decryption with SIMD
****************************************************************************/

// Encrypt SIMD_ENCRYPT_SIZE * N byte data with AVX2 or NEON
// dat_siz: must be divisible by 32 * HNC_RANK (= SIMD_ENCRYPT_SIZE)
static inline void
Mod16EncSIMD(HNCdatS *hnc_dat, const void *org_dat, void *enc_dat,
	     size_t dat_siz)
{
	uint8_t		*input_dat = (uint8_t *)org_dat;
	uint8_t		*output_dat = (uint8_t *)enc_dat;
	uint8_t		*end_in = input_dat + dat_siz;
	uint64_t	i, /*j, */key_idx;
	VEC_T		output[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		tmp, *_out, *output_end;
	VEC_T		(*key_beta_v)[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		*_key_beta_v, *prev_c_prime, *_prev_c_prime;
#if defined(__AVX2__)
	VEC_T		input, *tb, *_tb;
#elif defined(_arm64_)
	uint16x8_t	input0, input1, *tb, *_tb;
#endif

	// Initialize
	tb = hnc_dat->tb_enc;
	key_idx = hnc_dat->key_idx;
	key_beta_v = hnc_dat->key_beta_v;
	prev_c_prime = hnc_dat->prev_c_prime;
	output_end = output + (SIMD_ENCRYPT_SIZE / sizeof(VEC_T));

	// Add _prev_c_prime to first SIMD_ENCRYPT_SIZE data
	if (hnc_dat->inited) {
		// Initialize
		_tb = tb;
		_key_beta_v = key_beta_v[key_idx];
		_prev_c_prime = prev_c_prime;

#if defined(__AVX2__)
		// Load
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += 32; // 256bit

		// Add _prev_c_prime
		input = _mm256_add_epi16(input, *_prev_c_prime);
		_prev_c_prime++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi16(input, *_tb);
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load 256bit
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += 32; // 256bit

			// Add _prev_c_prime
			input = _mm256_add_epi16(input, *_prev_c_prime);
			_prev_c_prime++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi16(input, *_tb);
				*_out = _mm256_add_epi16(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Add key_beta, XOR with prev_c_prime and save
		_prev_c_prime = prev_c_prime;
		for (i = 0; i < HNC_RANK; i++) {
			// Add key_beta
			tmp = _mm256_add_epi16(output[i], *_key_beta_v);
			_key_beta_v++;

			// XOR prev_c_prime and save
			_mm256_storeu_si256((VEC_T *)output_dat,
				_mm256_xor_si256(tmp, *_prev_c_prime));
			*_prev_c_prime = tmp;
			_prev_c_prime++;
			output_dat += 32;
		}

#elif defined(_arm64_)
		// Load 128x2bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// Add _prev_c_prime
		input0 = vaddq_u16(input0, *_prev_c_prime);
		_prev_c_prime++;
		input1 = vaddq_u16(input1, *_prev_c_prime);
		_prev_c_prime++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u16(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u16(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load 128x2bit
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// Add _prev_c_prime
			input0 = vaddq_u16(input0, *_prev_c_prime);
			_prev_c_prime++;
			input1 = vaddq_u16(input1, *_prev_c_prime);
			_prev_c_prime++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u16(input0, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++; 
				tmp = vmulq_u16(input1, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Add key_beta, XOR with prev_c_prime and save
		_prev_c_prime = prev_c_prime;
		for (i = 0; i < HNC_RANK * 2; i++) {
			// Add key_beta
			tmp = vaddq_u16(output[i], *_key_beta_v);
			_key_beta_v++;

			// XOR with prev_c_prime and save
			vst1q_u8(output_dat, veorq_u64(tmp, *_prev_c_prime));
			*_prev_c_prime = tmp;
			_prev_c_prime++;
			output_dat += 16;
		}
#endif

		// No more initial data
		hnc_dat->inited = false;

		// Update key_idx
		if (key_idx == NUM_BETA_KEYS - 1) {
			key_idx = 0;
		}
		else {
			key_idx++;
		}
	}

	// Encrypt
	while (input_dat < end_in) {
		// Initialize for this iteration
		_tb = tb;
		_key_beta_v = key_beta_v[key_idx];
		_prev_c_prime = prev_c_prime;

#if defined(__AVX2__)
		// Load input
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += 32; // 256bit

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi16(input, *_tb);
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load 256bit
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += 32; // 256bit

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi16(input, *_tb);
				*_out = _mm256_add_epi16(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Add key_beta, XOR with prev_c_prime and save
		_prev_c_prime = prev_c_prime;
		for (i = 0; i < HNC_RANK; i++) {
			// Add key_beta
			tmp = _mm256_add_epi16(output[i], *_key_beta_v);
			_key_beta_v++;

			// XOR prev_c_prime and save
			_mm256_storeu_si256((VEC_T *)output_dat,
				_mm256_xor_si256(tmp, *_prev_c_prime));
			*_prev_c_prime = tmp;
			_prev_c_prime++;
			output_dat += 32;
		}

#elif defined(_arm64_)
		// Load 128x2bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u16(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u16(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load 128x2bit
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u16(input0, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++; 
				tmp = vmulq_u16(input1, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Add key_beta, XOR with prev_c_prime and save
		for (i = 0; i < HNC_RANK * 2; i++) {
			// Add key_beta
			tmp = vaddq_u16(output[i], *_key_beta_v);
			_key_beta_v++;

			// XOR with prev_c_prime and save
			vst1q_u8(output_dat, veorq_u64(tmp, *_prev_c_prime));
			*_prev_c_prime = tmp;
			_prev_c_prime++;
			output_dat += 16;
		}
#endif

		// Update key_idx
		if (key_idx == NUM_BETA_KEYS - 1) {
			key_idx = 0;
		}
		else {
			key_idx++;
		}
	}
}

// Encrypt data < SIMD_ENCRYPT_SIZE bytes with AVX2 or NEON with padding
// Max padding size is 2 * HNC_RANK - 1 (7bytes for HNC_RANK = 4)
// dat_siz: Must be < 32 * HNC_RANK (i.e., < SIMD_ENCRYPT_SIZE)
static inline void
Mod16EncSIMDRem(HNCdatS *hnc_dat, const void *org_dat, void *enc_dat,
		size_t dat_siz)
{
	uint8_t		*input_dat, *output_dat;
	uint8_t		in_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint8_t		out_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint64_t	i, key_idx, *p;
	size_t		main_size, each_main_size, rem_size, size;
	lldiv_t		dv;
	VEC_T		output[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		tmp, *_out, *output_end;
	VEC_T		*_key_beta_v, *_prev_c_prime;
#if defined(__AVX2__)
	VEC_T		input, *_tb;
#elif defined(_arm64_)
	uint16x8_t	input0, input1, *_tb;
#endif

	// Initialize
	_tb = hnc_dat->tb_enc;
	key_idx = hnc_dat->key_idx;
	_key_beta_v = hnc_dat->key_beta_v[key_idx];
	_prev_c_prime = hnc_dat->prev_c_prime;
	output_end = output + (SIMD_ENCRYPT_SIZE / sizeof(VEC_T));

	// Calculate main and remaining sizes
	dv = lldiv(dat_siz, sizeof(MOD_T) * HNC_RANK);
	each_main_size = dv.quot * sizeof(MOD_T);
	rem_size = dv.rem;
	main_size = dat_siz - rem_size;

	// Fill rem data part in in_buf with random numbers
	size = (main_size / 8) * 8;
	p = (uint64_t *)(in_buf + size);
	size = SIMD_ENCRYPT_SIZE - size;
	if (size >= 32) {
		i = 4;
	}
	else {
		i = size / 8;
	}
	for (; i; i--) {
		*p = sfmt_genrand_uint64(&hnc_dat->sfmt);
		p++;
	}

	// Adjust each_main_size
	if (rem_size) { // Remaining size not zero
		// Adjust each_main_size so each_main_size contains rem data
		each_main_size += sizeof(MOD_T);
	}

	// Copy org_dat to in_buf
	memcpy(in_buf, org_dat, dat_siz);
	input_dat = in_buf;
	output_dat = out_buf;

	// Encrypt
#if defined(__AVX2__)
	if (each_main_size) {
		// Load
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += each_main_size; // each_main_size byte

		// Add _prev_c_prime
		input = _mm256_add_epi16(input, *_prev_c_prime);
		_prev_c_prime++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi16(input, *_tb);
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += each_main_size; // each_main_size byte

			// Add _prev_c_prime
			input = _mm256_add_epi16(input, *_prev_c_prime);
			_prev_c_prime++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi16(input, *_tb);
				*_out = _mm256_add_epi16(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// XOR key_beta and save
		_out = output;
		for (i = 0; i < HNC_RANK; i++) {
			// XOR key_beta
			tmp = _mm256_xor_si256(*_out, *_key_beta_v);
			_key_beta_v++;
			_out++;

			// Save
			_mm256_storeu_si256((VEC_T *)output_dat, tmp);
			output_dat += each_main_size; // each_main_size byte
		}
	}

#elif defined(_arm64_)
	if (each_main_size) {
		// Load each_main_size byte
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += each_main_size - 16; // each_main_size byte

		// Add _prev_c_prime
		input0 = vaddq_u16(input0, *_prev_c_prime);
		_prev_c_prime++;
		input1 = vaddq_u16(input1, *_prev_c_prime);
		_prev_c_prime++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u16(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u16(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load each_main_size byte
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += each_main_size - 16; // each_main_size byte

			// Add _prev_c_prime
			input0 = vaddq_u16(input0, *_prev_c_prime);
			_prev_c_prime++;
			input1 = vaddq_u16(input1, *_prev_c_prime);
			_prev_c_prime++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u16(input0, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++;
				tmp = vmulq_u16(input1, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// XOR key_beta and save
		_out = output;
		for (i = 0; i < HNC_RANK; i++) {
			// XOR key_beta
			tmp = veorq_u64(*_out, *_key_beta_v);
			_key_beta_v++;
			_out++;

			// Save
			vst1q_u8(output_dat, tmp);
			output_dat += 16;

			// XOR key_beta
			tmp = veorq_u64(*_out, *_key_beta_v);
			_key_beta_v++;
			_out++;

			// Save
			vst1q_u8(output_dat, tmp);
			output_dat += each_main_size - 16;
		}
	}
#endif

	// Copy out_buf to enc_dat
	memcpy(enc_dat, out_buf, each_main_size * HNC_RANK);

	// Padding size is each_main_size * HNC_RANK - dat_siz
	// which is < sizeof(MOD_T) * HNC_RANK
}

// Encrypt data < SIMD_ENCRYPT_SIZE bytes with AVX2 or NEON without padding
// dat_siz: Must be < 32 * HNC_RANK (i.e., < SIMD_ENCRYPT_SIZE)
// Note: This is not secure yet and should be improved
static inline void
Mod16EncSIMDRemNoPad(HNCdatS *hnc_dat, const void *org_dat, void *enc_dat,
		     size_t dat_siz)
{
	uint8_t		*input_dat, *output_dat;
	uint8_t		in_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint8_t		out_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint64_t	i, key_idx;
	size_t		/*main_size,*/each_main_size, rem_size;
	lldiv_t		dv;
	VEC_T		output[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		tmp, *_out, *output_end, rem_v;
	VEC_T		*_key_beta_v, *_prev_c_prime;
#if defined(__AVX2__)
	VEC_T		input, *_tb;
#elif defined(_arm64_)
	uint16x8_t	input0, input1, *_tb;
#endif

	// Initialize
	_tb = hnc_dat->tb_enc;
	key_idx = hnc_dat->key_idx;
	_key_beta_v = hnc_dat->key_beta_v[key_idx];
	_prev_c_prime = hnc_dat->prev_c_prime;
	output_end = output + (SIMD_ENCRYPT_SIZE / sizeof(VEC_T));

	// Calculate main and remaining sizes
	dv = lldiv(dat_siz, sizeof(MOD_T) * HNC_RANK);
	each_main_size = dv.quot * sizeof(MOD_T);
	//main_size = each_main_size * HNC_RANK;
	rem_size = dv.rem;

	// Copy org_dat to buf
	memcpy(in_buf, org_dat, dat_siz);
	input_dat = in_buf;
	output_dat = out_buf;

	// Encrypt
#if defined(__AVX2__)
	if (each_main_size) {
		// Load
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += each_main_size; // each_main_size byte

		// Add _prev_c_prime
		input = _mm256_add_epi16(input, *_prev_c_prime);
		_prev_c_prime++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi16(input, *_tb);
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += each_main_size; // each_main_size byte

			// Add _prev_c_prime
			input = _mm256_add_epi16(input, *_prev_c_prime);
			_prev_c_prime++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi16(input, *_tb);
				*_out = _mm256_add_epi16(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// XOR key_beta and save
		_out = output;
		for (i = 0; i < HNC_RANK; i++) {
			// XOR key_beta
			tmp = _mm256_xor_si256(*_out, *_key_beta_v);
			_key_beta_v++;
			_out++;

			// Save
			_mm256_storeu_si256((VEC_T *)output_dat, tmp);
			output_dat += each_main_size; // each_main_size byte
		}
	}

	// Encrypt rem data
	if (rem_size) {
		// Load
		rem_v = _mm256_loadu_si256((VEC_T *)input_dat);

		// XOR _key_beta_v
		tmp = _mm256_xor_si256(rem_v, hnc_dat->key_beta_v_0);

		// Add _prev_c_prime
		rem_v =  _mm256_add_epi16(tmp, hnc_dat->prev_c_prime_0);

		// Save
		_mm256_storeu_si256((VEC_T *)output_dat, rem_v);
	}

#elif defined(_arm64_)
	if (each_main_size) {
		// Load each_main_size byte
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += each_main_size - 16; // each_main_size byte

		// Add _prev_c_prime
		input0 = vaddq_u16(input0, *_prev_c_prime);
		_prev_c_prime++;
		input1 = vaddq_u16(input1, *_prev_c_prime);
		_prev_c_prime++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u16(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u16(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load each_main_size byte
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += each_main_size - 16; // each_main_size byte

			// Add _prev_c_prime
			input0 = vaddq_u16(input0, *_prev_c_prime);
			_prev_c_prime++;
			input1 = vaddq_u16(input1, *_prev_c_prime);
			_prev_c_prime++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u16(input0, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++;
				tmp = vmulq_u16(input1, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// XOR key_beta and save
		_out = output;
		for (i = 0; i < HNC_RANK; i++) {
			// XOR key_beta
			tmp = veorq_u64(*_out, *_key_beta_v);
			_key_beta_v++;
			_out++;

			// Save
			vst1q_u8(output_dat, tmp);
			output_dat += 16;

			// XOR key_beta
			tmp = veorq_u64(*_out, *_key_beta_v);
			_key_beta_v++;
			_out++;

			// Save
			vst1q_u8(output_dat, tmp);
			output_dat += each_main_size - 16;
		}
	}

	// Encrypt rem data
	if (rem_size) {
		// Load first 128bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _key_beta_v
		tmp = veorq_u64(input0, hnc_dat->key_beta_v_0);

		// Add _prev_c_prime
		rem_v = vaddq_u16(tmp, hnc_dat->prev_c_prime_0);

		// Save 128bit
		vst1q_u8(output_dat, rem_v);
		output_dat += 16;

		// Load second 128bit
		input1 = vld1q_u8(input_dat); // 128bit

		// XOR _key_beta_v
		tmp = veorq_u64(input1, hnc_dat->key_beta_v_1);

		// Add _prev_c_prime
		rem_v = vaddq_u16(tmp, hnc_dat->prev_c_prime_1);

		// Save 128bit
		vst1q_u8(output_dat, rem_v);
	}
#endif

	// Copy out_buf to enc_dat
	memcpy(enc_dat, out_buf, dat_siz);

#if 0 // Debug
	if (memcmp(org_dat, enc_dat, dat_siz)) {
		puts("error");
		ShowBytes(org_dat, dat_siz);
		ShowBytes(enc_dat, dat_siz);
		//mm_print256_8("", input);
		putchar('\n');
		exit(1);
	}
#endif
}

// Decrypt SIMD_ENCRYPT_SIZE * N byte data with AVX2 or NEON
// dat_siz: must be divisible by 32 * HNC_RANK (= SIMD_ENCRYPT_SIZE)
static inline void
Mod16DecSIMD(HNCdatS *hnc_dat, const void *enc_dat, void *dec_dat,
		  size_t dat_siz)
{
	uint8_t		*input_dat = (uint8_t *)enc_dat;
	uint8_t		*output_dat = (uint8_t *)dec_dat;
	uint8_t		*end_in = input_dat + dat_siz;
	uint64_t	i, /*j, */key_idx;
	VEC_T		output[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		tmp, *_out, *output_end;
	VEC_T		(*key_beta_v)[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		*_key_beta_v, *prev_c_prime, *_prev_c_prime;
#if defined(__AVX2__)
	VEC_T		input, *tb, *_tb;
#elif defined(_arm64_)
	uint16x8_t	input0, input1, *tb, *_tb;
#endif

	// Initialize
	tb = hnc_dat->tb_dec;
	key_idx = hnc_dat->key_idx;
	key_beta_v = hnc_dat->key_beta_v;
	prev_c_prime = hnc_dat->prev_c_prime;
	output_end = output + (SIMD_ENCRYPT_SIZE / sizeof(VEC_T));

	// Decrypt first data
	if (hnc_dat->inited) { // First data
		VEC_T	org_c_prime[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
		VEC_T	*_org_c_prime;

		// Initialize
		_tb = tb;
		_key_beta_v = key_beta_v[key_idx];
		_prev_c_prime = prev_c_prime;
		_org_c_prime = org_c_prime;

#if defined(__AVX2__)
		// Load 256bit
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += 32; // 256bit

		// XOR _prev_c_prime
		tmp = *_org_c_prime = *_prev_c_prime; 
		input = _mm256_xor_si256(input, tmp);
		*_prev_c_prime = input; // Save _prev_c_prime
		_prev_c_prime++;
		_org_c_prime++;

		// Subtract _key_beta_v
		input = _mm256_sub_epi16(input, *_key_beta_v);
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi16(input, *_tb);
			_tb++;
			_out++;
		}

		// XOR, subtract and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load 256bit
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += 32; // 256bit

			// XOR _prev_c_prime
			tmp = *_org_c_prime = *_prev_c_prime; 
			input = _mm256_xor_si256(input, tmp);
			*_prev_c_prime = input; // Save _prev_c_prime
			_prev_c_prime++;
			_org_c_prime++;

			// Subtract _key_beta_v
			input = _mm256_sub_epi16(input, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi16(input, *_tb);
				*_out = _mm256_add_epi16(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Save output
		_out = output;
		_org_c_prime = org_c_prime;

		// Subtract _org_c_prime from output
		while (_out < output_end) {
			// Subtract _prev_c_prime
			tmp = _mm256_sub_epi16(*_out, *_org_c_prime);
			_out++;
			_org_c_prime++;

			// Save
			_mm256_storeu_si256((VEC_T *)output_dat, tmp);
			output_dat += 32;
		}

#elif defined(_arm64_)
		// Load first 128bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _prev_c_prime
		tmp = *_org_c_prime = *_prev_c_prime;
		input0 = veorq_u64(input0, tmp);
		*_prev_c_prime = input0; // 128bit
		_prev_c_prime++;
		_org_c_prime++;

		// Subtract _key_beta_v
		input0 = vsubq_u16(input0, *_key_beta_v);
		_key_beta_v++;

		// Load second 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _prev_c_prime
		tmp = *_org_c_prime = *_prev_c_prime;
		input1 = veorq_u64(input1, tmp);
		*_prev_c_prime = input1;
		_prev_c_prime++;
		_org_c_prime++;

		// Subtract _key_beta_v
		input1 = vsubq_u16(input1, *_key_beta_v); // 128bit
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u16(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u16(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// XOR, subtract and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load first 128bit
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// XOR _prev_c_prime
			tmp = *_org_c_prime = *_prev_c_prime;
			input0 = veorq_u64(input0, tmp);
			*_prev_c_prime = input0; // 128bit
			_prev_c_prime++;
			_org_c_prime++;

			// Subtract _key_beta_v
			input0 = vsubq_u16(input0, *_key_beta_v);
			_key_beta_v++;

			// Load second 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// XOR _prev_c_prime
			tmp = *_org_c_prime = *_prev_c_prime;
			input1 = veorq_u64(input1, tmp);
			*_prev_c_prime = input1; // 128bit
			_prev_c_prime++;
			_org_c_prime++;

			// Subtract _key_beta_v
			input1 = vsubq_u16(input1, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u16(input0, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++;
				tmp = vmulq_u16(input1, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// Save output
		_out = output;
		_org_c_prime = org_c_prime;

		// Subtract _org_c_prime from output
		while (_out < output_end) {
			// Subtract _org_c_prime
			tmp = vsubq_u16(*_out, *_org_c_prime);
			_out++;
			_org_c_prime++;

			// Save
			vst1q_u8(output_dat, tmp); // 128bit
			output_dat += 16; // 128bit
		}
#endif

		hnc_dat->inited = false;

		// Update key_idx
		if (key_idx == NUM_BETA_KEYS - 1) {
			key_idx = 0;
		}
		else {
			key_idx++;
		}
	}

	// Decrypt
	while (input_dat < end_in) {
		// Initialize for this iteration
		_tb = tb;
		_key_beta_v = key_beta_v[key_idx];
		_prev_c_prime = prev_c_prime;

#if defined(__AVX2__)
		// Load 256bit
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += 32; // 256bit

		// XOR _prev_c_prime
		input = _mm256_xor_si256(input, *_prev_c_prime);
		*_prev_c_prime = input; // Save _prev_c_prime
		_prev_c_prime++;

		// Subtract _key_beta_v
		input = _mm256_sub_epi16(input, *_key_beta_v);
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi16(input, *_tb);
			_tb++;
			_out++;
		}

		// XOR, subtract and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load 256bit
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += 32; // 256bit

			// XOR _prev_c_prime
			input = _mm256_xor_si256(input, *_prev_c_prime);
			*_prev_c_prime = input; // Save _prev_c_prime
			_prev_c_prime++;

			// Subtract _key_beta_v
			input = _mm256_sub_epi16(input, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi16(input, *_tb);
				*_out = _mm256_add_epi16(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Save output
		_out = output;
		while (_out < output_end) {
			// Save
			_mm256_storeu_si256((VEC_T *)output_dat, *_out);
			output_dat += 32;
			_out++;
		}

#elif defined(_arm64_)
		// Load first 128bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _prev_c_prime
		input0 = veorq_u64(input0, *_prev_c_prime);
		*_prev_c_prime = input0; // 128bit
		_prev_c_prime++;

		// Subtract _key_beta_v
		input0 = vsubq_u16(input0, *_key_beta_v);
		_key_beta_v++;

		// Load second 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _prev_c_prime
		input1 = veorq_u64(input1, *_prev_c_prime);
		*_prev_c_prime = input1;
		_prev_c_prime++;

		// Subtract _key_beta_v
		input1 = vsubq_u16(input1, *_key_beta_v); // 128bit
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u16(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u16(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// XOR, subtract and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load first 128bit
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// XOR _prev_c_prime
			input0 = veorq_u64(input0, *_prev_c_prime);
			*_prev_c_prime = input0; // 128bit
			_prev_c_prime++;

			// Subtract _key_beta_v
			input0 = vsubq_u16(input0, *_key_beta_v);
			_key_beta_v++;

			// Load second 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// XOR _prev_c_prime
			input1 = veorq_u64(input1, *_prev_c_prime);
			*_prev_c_prime = input1; // 128bit
			_prev_c_prime++;

			// Subtract _key_beta_v
			input1 = vsubq_u16(input1, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u16(input0, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++;
				tmp = vmulq_u16(input1, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// Save output
		_out = output;
		while (_out < output_end) {
			vst1q_u8(output_dat, *_out); // 128bit
			output_dat += 16; // 128bit
			_out++;
		}
#endif

		// Update key_idx
		if (key_idx == NUM_BETA_KEYS - 1) {
			key_idx = 0;
		}
		else {
			key_idx++;
		}
	}
}

// Decrypt data < SIMD_ENCRYPT_SIZE bytes with AVX2 or NEON with padding
// Max padding size is 2 * HNC_RANK - 1 (7bytes for HNC_RANK = 4)
// dat_siz: Must be < 32 * HNC_RANK (i.e., < SIMD_ENCRYPT_SIZE)
static inline void
Mod16DecSIMDRem(HNCdatS *hnc_dat, const void *enc_dat, void *dec_dat,
		     size_t dat_siz)
{
	uint8_t		*input_dat, *output_dat;
	uint8_t		in_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint8_t		out_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint64_t	i, key_idx;
	size_t		each_main_size, rem_size, padded_dat_siz;
	lldiv_t		dv;
	VEC_T		output[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		tmp, *_out, *output_end;
	VEC_T		*_key_beta_v, *_prev_c_prime;
#if defined(__AVX2__)
	VEC_T		input, *_tb;
#elif defined(_arm64_)
	uint16x8_t	input0, input1, *_tb;
#endif

	// Initialize
	_tb = hnc_dat->tb_dec;
	key_idx = hnc_dat->key_idx;
	_key_beta_v = hnc_dat->key_beta_v[key_idx];
	_prev_c_prime = hnc_dat->prev_c_prime;
	output_end = output + (SIMD_ENCRYPT_SIZE / sizeof(VEC_T));

	// Calculate main and remaining sizes
	dv = lldiv(dat_siz, sizeof(MOD_T) * HNC_RANK);
	each_main_size = dv.quot * sizeof(MOD_T);
	rem_size = dv.rem;

	// Adjust each_main_size
	if (rem_size) { // Remaining size not zero
		// Adjust each_main_size so each_main_size contains rem data
		each_main_size += sizeof(MOD_T);
	}

	// Calculate padded data size
	padded_dat_siz = each_main_size * HNC_RANK;

	// Copy enc_dat to buf
	memcpy(in_buf, enc_dat, padded_dat_siz);
	input_dat = in_buf;
	output_dat = out_buf;

	// Decrypt
#if defined(__AVX2__)
	if (each_main_size) {
		// Load
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += each_main_size; // each_main_size byte

		// XOR _key_beta_v
		input = _mm256_xor_si256(input, *_key_beta_v);
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi16(input, *_tb);
			_tb++;
			_out++;
		}

		// XOR and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += each_main_size; // each_main_size byte
	
			// XOR _key_beta_v
			input = _mm256_xor_si256(input, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi16(input, *_tb);
				*_out = _mm256_add_epi16(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Subtract _prev_c_prime and save output
		for (i = 0; i < HNC_RANK; i++) {
			tmp = _mm256_sub_epi16(output[i], *_prev_c_prime);
			_prev_c_prime++;
			_mm256_storeu_si256((VEC_T *)output_dat, tmp);
			output_dat += each_main_size;
		}
	}

#elif defined(_arm64_)
	if (each_main_size) {
		// Load first 128bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _key_beta_v
		input0 = veorq_u64(input0, *_key_beta_v);
		_key_beta_v++;

		// Load second 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += each_main_size - 16; // Proceed each_main_size byte

		// XOR _key_beta_v
		input1 = veorq_u64(input1, *_key_beta_v);
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u16(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u16(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// XOR, subtract and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load first 128bit
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// XOR _key_beta_v
			input0 = veorq_u64(input0, *_key_beta_v);
			_key_beta_v++;

			// Load second 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += each_main_size - 16; // Proceed 
							  // each_main_size byte

			// XOR _key_beta_v
			input1 = veorq_u64(input1, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u16(input0, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++;
				tmp = vmulq_u16(input1, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// Save output
		_out = output;
		for (i = 0; i < HNC_RANK; i++) {
			// Subtract _prev_c_prime
			tmp = vsubq_u16(*_out, *_prev_c_prime);
			_prev_c_prime++;

			// Save
			vst1q_u8(output_dat, tmp); // 128bit
			output_dat += 16; // 128bit
			_out++;

			// Subtract _prev_c_prime
			tmp = vsubq_u16(*_out, *_prev_c_prime);
			_prev_c_prime++;

			// Save
			vst1q_u8(output_dat, tmp); // 128bit
			output_dat += each_main_size - 16; // 128bit
			_out++;
		}
	}

#endif

	// Copy out_buf to dec_dat
	memcpy(dec_dat, out_buf, dat_siz);
}

// Decrypt data < SIMD_ENCRYPT_SIZE bytes with AVX2 or NEON without padding
// dat_siz: Must be < 32 * HNC_RANK (i.e., < SIMD_ENCRYPT_SIZE)
// Note: This is not secure yet and should be improved
static inline void
Mod16DecSIMDRemNoPad(HNCdatS *hnc_dat, const void *enc_dat, void *dec_dat,
		     size_t dat_siz)
{
	uint8_t		*input_dat, *output_dat;
	uint8_t		in_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint8_t		out_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint64_t	i, key_idx;
	size_t		/*main_size,*/each_main_size, rem_size;
	lldiv_t		dv;
	VEC_T		tmp, *_out, *output_end, rem_v;
	VEC_T		output[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		*_key_beta_v, *_prev_c_prime;
#if defined(__AVX2__)
	VEC_T		input, *_tb;
#elif defined(_arm64_)
	uint16x8_t	input0, input1, *_tb;
#endif

	// Initialize
	_tb = hnc_dat->tb_dec;
	key_idx = hnc_dat->key_idx;
	_key_beta_v = hnc_dat->key_beta_v[key_idx];
	_prev_c_prime = hnc_dat->prev_c_prime;
	output_end = output + (SIMD_ENCRYPT_SIZE / sizeof(VEC_T));

	// Calculate main and remaining sizes
	dv = lldiv(dat_siz, sizeof(MOD_T) * HNC_RANK);
	each_main_size = dv.quot * sizeof(MOD_T);
	//main_size = each_main_size * HNC_RANK;
	rem_size = dv.rem;

	// Copy enc_dat to buf
	memcpy(in_buf, enc_dat, dat_siz);
	input_dat = in_buf;
	output_dat = out_buf;

	// Decrypt
#if defined(__AVX2__)
	if (each_main_size) {
		// Load
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += each_main_size; // each_main_size byte

		// XOR _key_beta_v
		input = _mm256_xor_si256(input, *_key_beta_v);
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi16(input, *_tb);
			_tb++;
			_out++;
		}

		// XOR and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += each_main_size; // each_main_size byte
	
			// XOR _key_beta_v
			input = _mm256_xor_si256(input, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi16(input, *_tb);
				*_out = _mm256_add_epi16(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Subtract _prev_c_prime and save output
		for (i = 0; i < HNC_RANK; i++) {
			tmp = _mm256_sub_epi16(output[i], *_prev_c_prime);
			_prev_c_prime++;
			_mm256_storeu_si256((VEC_T *)output_dat, tmp);
			output_dat += each_main_size;
		}
	}

	// Decrypt rem data
	if (rem_size) {
		// Load
		rem_v = _mm256_loadu_si256((VEC_T *)input_dat);

		// Subtract prev_c_prime_0
		tmp =  _mm256_sub_epi16(rem_v, hnc_dat->prev_c_prime_0);

		// XOR _key_beta_v
		rem_v = _mm256_xor_si256(tmp, hnc_dat->key_beta_v_0);

		// Save
		_mm256_storeu_si256((VEC_T *)output_dat, rem_v);
	}

#elif defined(_arm64_)
	if (each_main_size) {
		// Load first 128bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _key_beta_v
		input0 = veorq_u64(input0, *_key_beta_v);
		_key_beta_v++;

		// Load second 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += each_main_size - 16; // Proceed each_main_size byte

		// XOR _key_beta_v
		input1 = veorq_u64(input1, *_key_beta_v);
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u16(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u16(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// XOR, subtract and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load first 128bit
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// XOR _key_beta_v
			input0 = veorq_u64(input0, *_key_beta_v);
			_key_beta_v++;

			// Load second 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += each_main_size - 16; // Proceed 
							  // each_main_size byte

			// XOR _key_beta_v
			input1 = veorq_u64(input1, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u16(input0, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++;
				tmp = vmulq_u16(input1, *_tb); // 128bit
				*_out = vaddq_u16(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// Save output
		_out = output;
		for (i = 0; i < HNC_RANK; i++) {
			// Subtract _prev_c_prime
			tmp = vsubq_u16(*_out, *_prev_c_prime);
			_prev_c_prime++;

			// Save
			vst1q_u8(output_dat, tmp); // 128bit
			output_dat += 16; // 128bit
			_out++;

			// Subtract _prev_c_prime
			tmp = vsubq_u16(*_out, *_prev_c_prime);
			_prev_c_prime++;

			// Save
			vst1q_u8(output_dat, tmp); // 128bit
			output_dat += each_main_size - 16; // 128bit
			_out++;
		}
	}

	// Decrypt rem data
	if (rem_size) {
		// Load first 128bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// Subtract prev_c_prime_0
		input0 = vsubq_u16(input0, hnc_dat->prev_c_prime_0);

		// XOR _key_beta_v
		rem_v = veorq_u64(input0, hnc_dat->key_beta_v_0);

		// Save 128bit
		vst1q_u8(output_dat, rem_v);
		output_dat += 16;

		// Load second 128bit
		input1 = vld1q_u8(input_dat); // 128bit

		// Subtract prev_c_prime_1
		input1 = vsubq_u16(input1, hnc_dat->prev_c_prime_1);

		// XOR _key_beta_v
		rem_v = veorq_u64(input1, hnc_dat->key_beta_v_1);

		// Save 128bit
		vst1q_u8(output_dat, rem_v);
	}

#endif

	// Copy out_buf to dec_dat
	memcpy(dec_dat, out_buf, dat_siz);
}

#elif defined(_MOD32_)
/****************************************************************************
	32bit encryption and decryption with SIMD
****************************************************************************/

// Encrypt SIMD_ENCRYPT_SIZE * N byte data with AVX2 or NEON
// dat_siz: must be divisible by 32 * HNC_RANK (= SIMD_ENCRYPT_SIZE)
static inline void
Mod32EncSIMD(HNCdatS *hnc_dat, const void *org_dat, void *enc_dat,
		  size_t dat_siz)
{
	uint8_t		*input_dat = (uint8_t *)org_dat;
	uint8_t		*output_dat = (uint8_t *)enc_dat;
	uint8_t		*end_in = input_dat + dat_siz;
	uint64_t	i, /*j, */key_idx;
	VEC_T		output[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		tmp, *_out, *output_end;
	VEC_T		(*key_beta_v)[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		*_key_beta_v, *prev_c_prime, *_prev_c_prime;
#if defined(__AVX2__)
	VEC_T		input, *tb, *_tb;
#elif defined(_arm64_)
	uint32x4_t	input0, input1, *tb, *_tb;
#endif

	// Initialize
	tb = hnc_dat->tb_enc;
	key_idx = hnc_dat->key_idx;
	key_beta_v = hnc_dat->key_beta_v;
	prev_c_prime = hnc_dat->prev_c_prime;
	output_end = output + (SIMD_ENCRYPT_SIZE / sizeof(VEC_T));

	// Add _prev_c_prime to first SIMD_ENCRYPT_SIZE data
	if (hnc_dat->inited) {
		// Initialize
		_tb = tb;
		_key_beta_v = key_beta_v[key_idx];
		_prev_c_prime = prev_c_prime;

#if defined(__AVX2__)
		// Load
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += 32; // 256bit

		// Add _prev_c_prime
		input = _mm256_add_epi32(input, *_prev_c_prime);
		_prev_c_prime++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi32(input, *_tb);
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load 256bit
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += 32; // 256bit

			// Add _prev_c_prime
			input = _mm256_add_epi32(input, *_prev_c_prime);
			_prev_c_prime++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi32(input, *_tb);
				*_out = _mm256_add_epi32(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Add key_beta, XOR with prev_c_prime and save
		_prev_c_prime = prev_c_prime;
		for (i = 0; i < HNC_RANK; i++) {
			// Add key_beta
			tmp = _mm256_add_epi32(output[i], *_key_beta_v);
			_key_beta_v++;

			// XOR prev_c_prime and save
			_mm256_storeu_si256((VEC_T *)output_dat,
				_mm256_xor_si256(tmp, *_prev_c_prime));
			*_prev_c_prime = tmp;
			_prev_c_prime++;
			output_dat += 32;
		}

#elif defined(_arm64_)
		// Load 128x2bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// Add _prev_c_prime
		input0 = vaddq_u32(input0, *_prev_c_prime);
		_prev_c_prime++;
		input1 = vaddq_u32(input1, *_prev_c_prime);
		_prev_c_prime++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u32(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u32(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load 128x2bit
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// Add _prev_c_prime
			input0 = vaddq_u32(input0, *_prev_c_prime);
			_prev_c_prime++;
			input1 = vaddq_u32(input1, *_prev_c_prime);
			_prev_c_prime++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u32(input0, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++; 
				tmp = vmulq_u32(input1, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Add key_beta, XOR with prev_c_prime and save
		_prev_c_prime = prev_c_prime;
		for (i = 0; i < HNC_RANK * 2; i++) {
			// Add key_beta
			tmp = vaddq_u32(output[i], *_key_beta_v);
			_key_beta_v++;

			// XOR with prev_c_prime and save
			vst1q_u8(output_dat, veorq_u64(tmp, *_prev_c_prime));
			*_prev_c_prime = tmp;
			_prev_c_prime++;
			output_dat += 16;
		}
#endif

		// No more initial data
		hnc_dat->inited = false;

		// Update key_idx
		if (key_idx == NUM_BETA_KEYS - 1) {
			key_idx = 0;
		}
		else {
			key_idx++;
		}
	}

	// Encrypt
	while (input_dat < end_in) {
		// Initialize for this iteration
		_tb = tb;
		_key_beta_v = key_beta_v[key_idx];
		_prev_c_prime = prev_c_prime;

#if defined(__AVX2__)
		// Load input
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += 32; // 256bit

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi32(input, *_tb);
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load 256bit
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += 32; // 256bit

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi32(input, *_tb);
				*_out = _mm256_add_epi32(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Add key_beta, XOR with prev_c_prime and save
		_prev_c_prime = prev_c_prime;
		for (i = 0; i < HNC_RANK; i++) {
			// Add key_beta
			tmp = _mm256_add_epi32(output[i], *_key_beta_v);
			_key_beta_v++;

			// XOR prev_c_prime and save
			_mm256_storeu_si256((VEC_T *)output_dat,
				_mm256_xor_si256(tmp, *_prev_c_prime));
			*_prev_c_prime = tmp;
			_prev_c_prime++;
			output_dat += 32;
		}

#elif defined(_arm64_)
		// Load 128x2bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u32(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u32(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load 128x2bit
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u32(input0, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++; 
				tmp = vmulq_u32(input1, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Add key_beta, XOR with prev_c_prime and save
		for (i = 0; i < HNC_RANK * 2; i++) {
			// Add key_beta
			tmp = vaddq_u32(output[i], *_key_beta_v);
			_key_beta_v++;

			// XOR with prev_c_prime and save
			vst1q_u8(output_dat, veorq_u64(tmp, *_prev_c_prime));
			*_prev_c_prime = tmp;
			_prev_c_prime++;
			output_dat += 16;
		}
#endif

		// Update key_idx
		if (key_idx == NUM_BETA_KEYS - 1) {
			key_idx = 0;
		}
		else {
			key_idx++;
		}
	}
}

// Encrypt data < SIMD_ENCRYPT_SIZE bytes with AVX2 or NEON with padding
// Max padding size is 4 * HNC_RANK - 1 (15bytes for HNC_RANK = 4)
// dat_siz: Must be < 32 * HNC_RANK (i.e., < SIMD_ENCRYPT_SIZE)
static inline void
Mod32EncSIMDRem(HNCdatS *hnc_dat, const void *org_dat, void *enc_dat,
		size_t dat_siz)
{
	uint8_t		*input_dat, *output_dat;
	uint8_t		in_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint8_t		out_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint64_t	i, key_idx, *p;
	size_t		main_size, each_main_size, rem_size, size;
	lldiv_t		dv;
	VEC_T		output[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		tmp, *_out, *output_end;
	VEC_T		*_key_beta_v, *_prev_c_prime;
#if defined(__AVX2__)
	VEC_T		input, *_tb;
#elif defined(_arm64_)
	uint32x4_t	input0, input1, *_tb;
#endif

	// Initialize
	_tb = hnc_dat->tb_enc;
	key_idx = hnc_dat->key_idx;
	_key_beta_v = hnc_dat->key_beta_v[key_idx];
	_prev_c_prime = hnc_dat->prev_c_prime;
	output_end = output + (SIMD_ENCRYPT_SIZE / sizeof(VEC_T));

	// Calculate main and remaining sizes
	dv = lldiv(dat_siz, sizeof(MOD_T) * HNC_RANK);
	each_main_size = dv.quot * sizeof(MOD_T);
	rem_size = dv.rem;
	main_size = dat_siz - rem_size;

	// Fill rem data part in in_buf with random numbers
	size = (main_size / 8) * 8;
	p = (uint64_t *)(in_buf + size);
	size = SIMD_ENCRYPT_SIZE - size;
	if (size >= 32) {
		i = 4;
	}
	else {
		i = size / 8;
	}
	for (; i; i--) {
		*p = sfmt_genrand_uint64(&hnc_dat->sfmt);
		p++;
	}

	// Adjust each_main_size
	if (rem_size) { // Remaining size not zero
		// Adjust each_main_size so each_main_size contains rem data
		each_main_size += sizeof(MOD_T);
	}

	// Copy org_dat to in_buf
	memcpy(in_buf, org_dat, dat_siz);
	input_dat = in_buf;
	output_dat = out_buf;

	// Encrypt
#if defined(__AVX2__)
	if (each_main_size) {
		// Load
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += each_main_size; // each_main_size byte

		// Add _prev_c_prime
		input = _mm256_add_epi32(input, *_prev_c_prime);
		_prev_c_prime++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi32(input, *_tb);
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += each_main_size; // each_main_size byte

			// Add _prev_c_prime
			input = _mm256_add_epi32(input, *_prev_c_prime);
			_prev_c_prime++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi32(input, *_tb);
				*_out = _mm256_add_epi32(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// XOR key_beta and save
		_out = output;
		for (i = 0; i < HNC_RANK; i++) {
			// XOR key_beta
			tmp = _mm256_xor_si256(*_out, *_key_beta_v);
			_key_beta_v++;
			_out++;

			// Save
			_mm256_storeu_si256((VEC_T *)output_dat, tmp);
			output_dat += each_main_size; // each_main_size byte
		}
	}

#elif defined(_arm64_)
	if (each_main_size) {
		// Load each_main_size byte
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += each_main_size - 16; // each_main_size byte

		// Add _prev_c_prime
		input0 = vaddq_u32(input0, *_prev_c_prime);
		_prev_c_prime++;
		input1 = vaddq_u32(input1, *_prev_c_prime);
		_prev_c_prime++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u32(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u32(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load each_main_size byte
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += each_main_size - 16; // each_main_size byte

			// Add _prev_c_prime
			input0 = vaddq_u32(input0, *_prev_c_prime);
			_prev_c_prime++;
			input1 = vaddq_u32(input1, *_prev_c_prime);
			_prev_c_prime++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u32(input0, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++;
				tmp = vmulq_u32(input1, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// XOR key_beta and save
		_out = output;
		for (i = 0; i < HNC_RANK; i++) {
			// XOR key_beta
			tmp = veorq_u64(*_out, *_key_beta_v);
			_key_beta_v++;
			_out++;

			// Save
			vst1q_u8(output_dat, tmp);
			output_dat += 16;

			// XOR key_beta
			tmp = veorq_u64(*_out, *_key_beta_v);
			_key_beta_v++;
			_out++;

			// Save
			vst1q_u8(output_dat, tmp);
			output_dat += each_main_size - 16;
		}
	}
#endif

	// Copy out_buf to enc_dat
	memcpy(enc_dat, out_buf, each_main_size * HNC_RANK);

	// Padding size is each_main_size * HNC_RANK - dat_siz
	// which is < sizeof(MOD_T) * HNC_RANK
}

// Encrypt data < SIMD_ENCRYPT_SIZE bytes with AVX2 or NEON without padding
// dat_siz: Must be < 32 * HNC_RANK (i.e., < SIMD_ENCRYPT_SIZE)
// Note: This is not secure yet and should be improved
static inline void
Mod32EncSIMDRemNoPad(HNCdatS *hnc_dat, const void *org_dat, void *enc_dat,
		     size_t dat_siz)
{
	uint8_t		*input_dat, *output_dat;
	uint8_t		in_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint8_t		out_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint64_t	i, key_idx;
	size_t		/*main_size,*/each_main_size, rem_size;
	lldiv_t		dv;
	VEC_T		output[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		tmp, *_out, *output_end, rem_v;
	VEC_T		*_key_beta_v, *_prev_c_prime;
#if defined(__AVX2__)
	VEC_T		input, *_tb;
#elif defined(_arm64_)
	uint32x4_t	input0, input1, *_tb;
#endif

	// Initialize
	_tb = hnc_dat->tb_enc;
	key_idx = hnc_dat->key_idx;
	_key_beta_v = hnc_dat->key_beta_v[key_idx];
	_prev_c_prime = hnc_dat->prev_c_prime;
	output_end = output + (SIMD_ENCRYPT_SIZE / sizeof(VEC_T));

	// Calculate main and remaining sizes
	dv = lldiv(dat_siz, sizeof(MOD_T) * HNC_RANK);
	each_main_size = dv.quot * sizeof(MOD_T);
	//main_size = each_main_size * HNC_RANK;
	rem_size = dv.rem;

	// Copy org_dat to buf
	memcpy(in_buf, org_dat, dat_siz);
	input_dat = in_buf;
	output_dat = out_buf;

	// Encrypt
#if defined(__AVX2__)
	if (each_main_size) {
		// Load
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += each_main_size; // each_main_size byte

		// Add _prev_c_prime
		input = _mm256_add_epi32(input, *_prev_c_prime);
		_prev_c_prime++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi32(input, *_tb);
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += each_main_size; // each_main_size byte

			// Add _prev_c_prime
			input = _mm256_add_epi32(input, *_prev_c_prime);
			_prev_c_prime++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi32(input, *_tb);
				*_out = _mm256_add_epi32(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// XOR key_beta and save
		_out = output;
		for (i = 0; i < HNC_RANK; i++) {
			// XOR key_beta
			tmp = _mm256_xor_si256(*_out, *_key_beta_v);
			_key_beta_v++;
			_out++;

			// Save
			_mm256_storeu_si256((VEC_T *)output_dat, tmp);
			output_dat += each_main_size; // each_main_size byte
		}
	}

	// Encrypt rem data
	if (rem_size) {
		// Load
		rem_v = _mm256_loadu_si256((VEC_T *)input_dat);

		// XOR _key_beta_v
		tmp = _mm256_xor_si256(rem_v, hnc_dat->key_beta_v_0);

		// Add _prev_c_prime
		rem_v =  _mm256_add_epi32(tmp, hnc_dat->prev_c_prime_0);

		// Save
		_mm256_storeu_si256((VEC_T *)output_dat, rem_v);
	}

#elif defined(_arm64_)
	if (each_main_size) {
		// Load each_main_size byte
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += each_main_size - 16; // each_main_size byte

		// Add _prev_c_prime
		input0 = vaddq_u32(input0, *_prev_c_prime);
		_prev_c_prime++;
		input1 = vaddq_u32(input1, *_prev_c_prime);
		_prev_c_prime++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u32(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u32(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load each_main_size byte
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += each_main_size - 16; // each_main_size byte

			// Add _prev_c_prime
			input0 = vaddq_u32(input0, *_prev_c_prime);
			_prev_c_prime++;
			input1 = vaddq_u32(input1, *_prev_c_prime);
			_prev_c_prime++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u32(input0, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++;
				tmp = vmulq_u32(input1, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// XOR key_beta and save
		_out = output;
		for (i = 0; i < HNC_RANK; i++) {
			// XOR key_beta
			tmp = veorq_u64(*_out, *_key_beta_v);
			_key_beta_v++;
			_out++;

			// Save
			vst1q_u8(output_dat, tmp);
			output_dat += 16;

			// XOR key_beta
			tmp = veorq_u64(*_out, *_key_beta_v);
			_key_beta_v++;
			_out++;

			// Save
			vst1q_u8(output_dat, tmp);
			output_dat += each_main_size - 16;
		}
	}

	// Encrypt rem data
	if (rem_size) {
		// Load first 128bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _key_beta_v
		tmp = veorq_u64(input0, hnc_dat->key_beta_v_0);

		// Add _prev_c_prime
		rem_v = vaddq_u32(tmp, hnc_dat->prev_c_prime_0);

		// Save 128bit
		vst1q_u8(output_dat, rem_v);
		output_dat += 16;

		// Load second 128bit
		input1 = vld1q_u8(input_dat); // 128bit

		// XOR _key_beta_v
		tmp = veorq_u64(input1, hnc_dat->key_beta_v_1);

		// Add _prev_c_prime
		rem_v = vaddq_u32(tmp, hnc_dat->prev_c_prime_1);

		// Save 128bit
		vst1q_u8(output_dat, rem_v);
	}
#endif

	// Copy out_buf to enc_dat
	memcpy(enc_dat, out_buf, dat_siz);

#if 0 // Debug
	if (memcmp(org_dat, enc_dat, dat_siz)) {
		puts("error");
		ShowBytes(org_dat, dat_siz);
		ShowBytes(enc_dat, dat_siz);
		//mm_print256_8("", input);
		putchar('\n');
		exit(1);
	}
#endif
}

// Decrypt SIMD_ENCRYPT_SIZE * N byte data with AVX2 or NEON
// dat_siz: must be divisible by 32 * HNC_RANK (= SIMD_ENCRYPT_SIZE)
static inline void
Mod32DecSIMD(HNCdatS *hnc_dat, const void *enc_dat, void *dec_dat,
		  size_t dat_siz)
{
	uint8_t		*input_dat = (uint8_t *)enc_dat;
	uint8_t		*output_dat = (uint8_t *)dec_dat;
	uint8_t		*end_in = input_dat + dat_siz;
	uint64_t	i, /*j, */key_idx;
	VEC_T		output[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		tmp, *_out, *output_end;
	VEC_T		(*key_beta_v)[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		*_key_beta_v, *prev_c_prime, *_prev_c_prime;
#if defined(__AVX2__)
	VEC_T		input, *tb, *_tb;
#elif defined(_arm64_)
	uint32x4_t	input0, input1, *tb, *_tb;
#endif

	// Initialize
	tb = hnc_dat->tb_dec;
	key_idx = hnc_dat->key_idx;
	key_beta_v = hnc_dat->key_beta_v;
	prev_c_prime = hnc_dat->prev_c_prime;
	output_end = output + (SIMD_ENCRYPT_SIZE / sizeof(VEC_T));

	// Decrypt first data
	if (hnc_dat->inited) { // First data
		VEC_T	org_c_prime[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
		VEC_T	*_org_c_prime;

		// Initialize
		_tb = tb;
		_key_beta_v = key_beta_v[key_idx];
		_prev_c_prime = prev_c_prime;
		_org_c_prime = org_c_prime;

#if defined(__AVX2__)
		// Load 256bit
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += 32; // 256bit

		// XOR _prev_c_prime
		tmp = *_org_c_prime = *_prev_c_prime; 
		input = _mm256_xor_si256(input, tmp);
		*_prev_c_prime = input; // Save _prev_c_prime
		_prev_c_prime++;
		_org_c_prime++;

		// Subtract _key_beta_v
		input = _mm256_sub_epi32(input, *_key_beta_v);
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi32(input, *_tb);
			_tb++;
			_out++;
		}

		// XOR, subtract and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load 256bit
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += 32; // 256bit

			// XOR _prev_c_prime
			tmp = *_org_c_prime = *_prev_c_prime; 
			input = _mm256_xor_si256(input, tmp);
			*_prev_c_prime = input; // Save _prev_c_prime
			_prev_c_prime++;
			_org_c_prime++;

			// Subtract _key_beta_v
			input = _mm256_sub_epi32(input, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi32(input, *_tb);
				*_out = _mm256_add_epi32(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Save output
		_out = output;
		_org_c_prime = org_c_prime;

		// Subtract _org_c_prime from output
		while (_out < output_end) {
			// Subtract _prev_c_prime
			tmp = _mm256_sub_epi32(*_out, *_org_c_prime);
			_out++;
			_org_c_prime++;

			// Save
			_mm256_storeu_si256((VEC_T *)output_dat, tmp);
			output_dat += 32;
		}

#elif defined(_arm64_)
		// Load first 128bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _prev_c_prime
		tmp = *_org_c_prime = *_prev_c_prime;
		input0 = veorq_u64(input0, tmp);
		*_prev_c_prime = input0; // 128bit
		_prev_c_prime++;
		_org_c_prime++;

		// Subtract _key_beta_v
		input0 = vsubq_u32(input0, *_key_beta_v);
		_key_beta_v++;

		// Load second 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _prev_c_prime
		tmp = *_org_c_prime = *_prev_c_prime;
		input1 = veorq_u64(input1, tmp);
		*_prev_c_prime = input1;
		_prev_c_prime++;
		_org_c_prime++;

		// Subtract _key_beta_v
		input1 = vsubq_u32(input1, *_key_beta_v); // 128bit
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u32(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u32(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// XOR, subtract and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load first 128bit
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// XOR _prev_c_prime
			tmp = *_org_c_prime = *_prev_c_prime;
			input0 = veorq_u64(input0, tmp);
			*_prev_c_prime = input0; // 128bit
			_prev_c_prime++;
			_org_c_prime++;

			// Subtract _key_beta_v
			input0 = vsubq_u32(input0, *_key_beta_v);
			_key_beta_v++;

			// Load second 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// XOR _prev_c_prime
			tmp = *_org_c_prime = *_prev_c_prime;
			input1 = veorq_u64(input1, tmp);
			*_prev_c_prime = input1; // 128bit
			_prev_c_prime++;
			_org_c_prime++;

			// Subtract _key_beta_v
			input1 = vsubq_u32(input1, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u32(input0, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++;
				tmp = vmulq_u32(input1, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// Save output
		_out = output;
		_org_c_prime = org_c_prime;

		// Subtract _org_c_prime from output
		while (_out < output_end) {
			// Subtract _org_c_prime
			tmp = vsubq_u32(*_out, *_org_c_prime);
			_out++;
			_org_c_prime++;

			// Save
			vst1q_u8(output_dat, tmp); // 128bit
			output_dat += 16; // 128bit
		}
#endif

		hnc_dat->inited = false;

		// Update key_idx
		if (key_idx == NUM_BETA_KEYS - 1) {
			key_idx = 0;
		}
		else {
			key_idx++;
		}
	}

	// Decrypt
	while (input_dat < end_in) {
		// Initialize for this iteration
		_tb = tb;
		_key_beta_v = key_beta_v[key_idx];
		_prev_c_prime = prev_c_prime;

#if defined(__AVX2__)
		// Load 256bit
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += 32; // 256bit

		// XOR _prev_c_prime
		input = _mm256_xor_si256(input, *_prev_c_prime);
		*_prev_c_prime = input; // Save _prev_c_prime
		_prev_c_prime++;

		// Subtract _key_beta_v
		input = _mm256_sub_epi32(input, *_key_beta_v);
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi32(input, *_tb);
			_tb++;
			_out++;
		}

		// XOR, subtract and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load 256bit
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += 32; // 256bit

			// XOR _prev_c_prime
			input = _mm256_xor_si256(input, *_prev_c_prime);
			*_prev_c_prime = input; // Save _prev_c_prime
			_prev_c_prime++;

			// Subtract _key_beta_v
			input = _mm256_sub_epi32(input, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi32(input, *_tb);
				*_out = _mm256_add_epi32(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Save output
		_out = output;
		while (_out < output_end) {
			// Save
			_mm256_storeu_si256((VEC_T *)output_dat, *_out);
			output_dat += 32;
			_out++;
		}

#elif defined(_arm64_)
		// Load first 128bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _prev_c_prime
		input0 = veorq_u64(input0, *_prev_c_prime);
		*_prev_c_prime = input0; // 128bit
		_prev_c_prime++;

		// Subtract _key_beta_v
		input0 = vsubq_u32(input0, *_key_beta_v);
		_key_beta_v++;

		// Load second 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _prev_c_prime
		input1 = veorq_u64(input1, *_prev_c_prime);
		*_prev_c_prime = input1;
		_prev_c_prime++;

		// Subtract _key_beta_v
		input1 = vsubq_u32(input1, *_key_beta_v); // 128bit
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u32(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u32(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// XOR, subtract and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load first 128bit
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// XOR _prev_c_prime
			input0 = veorq_u64(input0, *_prev_c_prime);
			*_prev_c_prime = input0; // 128bit
			_prev_c_prime++;

			// Subtract _key_beta_v
			input0 = vsubq_u32(input0, *_key_beta_v);
			_key_beta_v++;

			// Load second 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// XOR _prev_c_prime
			input1 = veorq_u64(input1, *_prev_c_prime);
			*_prev_c_prime = input1; // 128bit
			_prev_c_prime++;

			// Subtract _key_beta_v
			input1 = vsubq_u32(input1, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u32(input0, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++;
				tmp = vmulq_u32(input1, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// Save output
		_out = output;
		while (_out < output_end) {
			vst1q_u8(output_dat, *_out); // 128bit
			output_dat += 16; // 128bit
			_out++;
		}
#endif

		// Update key_idx
		if (key_idx == NUM_BETA_KEYS - 1) {
			key_idx = 0;
		}
		else {
			key_idx++;
		}
	}
}

// Decrypt data < SIMD_ENCRYPT_SIZE bytes with AVX2 or NEON with padding
// Max padding size is 4 * HNC_RANK - 1 (15bytes for HNC_RANK = 4)
// dat_siz: Must be < 32 * HNC_RANK (i.e., < SIMD_ENCRYPT_SIZE)
static inline void
Mod32DecSIMDRem(HNCdatS *hnc_dat, const void *enc_dat, void *dec_dat,
		size_t dat_siz)
{
	uint8_t		*input_dat, *output_dat;
	uint8_t		in_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint8_t		out_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint64_t	i, key_idx;
	size_t		each_main_size, rem_size, padded_dat_siz;
	lldiv_t		dv;
	VEC_T		output[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		tmp, *_out, *output_end;
	VEC_T		*_key_beta_v, *_prev_c_prime;
#if defined(__AVX2__)
	VEC_T		input, *_tb;
#elif defined(_arm64_)
	uint32x4_t	input0, input1, *_tb;
#endif

	// Initialize
	_tb = hnc_dat->tb_dec;
	key_idx = hnc_dat->key_idx;
	_key_beta_v = hnc_dat->key_beta_v[key_idx];
	_prev_c_prime = hnc_dat->prev_c_prime;
	output_end = output + (SIMD_ENCRYPT_SIZE / sizeof(VEC_T));

	// Calculate main and remaining sizes
	dv = lldiv(dat_siz, sizeof(MOD_T) * HNC_RANK);
	each_main_size = dv.quot * sizeof(MOD_T);
	rem_size = dv.rem;

	// Adjust each_main_size
	if (rem_size) { // Remaining size not zero
		// Adjust each_main_size so each_main_size contains rem data
		each_main_size += sizeof(MOD_T);
	}

	// Calculate padded data size
	padded_dat_siz = each_main_size * HNC_RANK;

	// Copy enc_dat to buf
	memcpy(in_buf, enc_dat, padded_dat_siz);
	input_dat = in_buf;
	output_dat = out_buf;

	// Decrypt
#if defined(__AVX2__)
	if (each_main_size) {
		// Load
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += each_main_size; // each_main_size byte

		// XOR _key_beta_v
		input = _mm256_xor_si256(input, *_key_beta_v);
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi32(input, *_tb);
			_tb++;
			_out++;
		}

		// XOR and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += each_main_size; // each_main_size byte
	
			// XOR _key_beta_v
			input = _mm256_xor_si256(input, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi32(input, *_tb);
				*_out = _mm256_add_epi32(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Subtract _prev_c_prime and save output
		for (i = 0; i < HNC_RANK; i++) {
			tmp = _mm256_sub_epi32(output[i], *_prev_c_prime);
			_prev_c_prime++;
			_mm256_storeu_si256((VEC_T *)output_dat, tmp);
			output_dat += each_main_size;
		}
	}

#elif defined(_arm64_)
	if (each_main_size) {
		// Load first 128bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _key_beta_v
		input0 = veorq_u64(input0, *_key_beta_v);
		_key_beta_v++;

		// Load second 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += each_main_size - 16; // Proceed each_main_size byte

		// XOR _key_beta_v
		input1 = veorq_u64(input1, *_key_beta_v);
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u32(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u32(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// XOR, subtract and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load first 128bit
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// XOR _key_beta_v
			input0 = veorq_u64(input0, *_key_beta_v);
			_key_beta_v++;

			// Load second 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += each_main_size - 16; // Proceed 
							  // each_main_size byte

			// XOR _key_beta_v
			input1 = veorq_u64(input1, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u32(input0, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++;
				tmp = vmulq_u32(input1, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// Save output
		_out = output;
		for (i = 0; i < HNC_RANK; i++) {
			// Subtract _prev_c_prime
			tmp = vsubq_u32(*_out, *_prev_c_prime);
			_prev_c_prime++;

			// Save
			vst1q_u8(output_dat, tmp); // 128bit
			output_dat += 16; // 128bit
			_out++;

			// Subtract _prev_c_prime
			tmp = vsubq_u32(*_out, *_prev_c_prime);
			_prev_c_prime++;

			// Save
			vst1q_u8(output_dat, tmp); // 128bit
			output_dat += each_main_size - 16; // 128bit
			_out++;
		}
	}

#endif

	// Copy out_buf to dec_dat
	memcpy(dec_dat, out_buf, dat_siz);
}

// Decrypt data < SIMD_ENCRYPT_SIZE bytes with AVX2 or NEON without padding
// dat_siz: Must be < 32 * HNC_RANK (i.e., < SIMD_ENCRYPT_SIZE)
// Note: This is not secure yet and should be improved
static inline void
Mod32DecSIMDRemNoPad(HNCdatS *hnc_dat, const void *enc_dat, void *dec_dat,
		     size_t dat_siz)
{
	uint8_t		*input_dat, *output_dat;
	uint8_t		in_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint8_t		out_buf[SIMD_ENCRYPT_SIZE + 32]; // Don't forget "+ 32"
	uint64_t	i, key_idx;
	size_t		/*main_size,*/each_main_size, rem_size;
	lldiv_t		dv;
	VEC_T		tmp, *_out, *output_end, rem_v;
	VEC_T		output[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		*_key_beta_v, *_prev_c_prime;
#if defined(__AVX2__)
	VEC_T		input, *_tb;
#elif defined(_arm64_)
	uint32x4_t	input0, input1, *_tb;
#endif

	// Initialize
	_tb = hnc_dat->tb_dec;
	key_idx = hnc_dat->key_idx;
	_key_beta_v = hnc_dat->key_beta_v[key_idx];
	_prev_c_prime = hnc_dat->prev_c_prime;
	output_end = output + (SIMD_ENCRYPT_SIZE / sizeof(VEC_T));

	// Calculate main and remaining sizes
	dv = lldiv(dat_siz, sizeof(MOD_T) * HNC_RANK);
	each_main_size = dv.quot * sizeof(MOD_T);
	//main_size = each_main_size * HNC_RANK;
	rem_size = dv.rem;

	// Copy enc_dat to buf
	memcpy(in_buf, enc_dat, dat_siz);
	input_dat = in_buf;
	output_dat = out_buf;

	// Decrypt
#if defined(__AVX2__)
	if (each_main_size) {
		// Load
		input = _mm256_loadu_si256((VEC_T *)input_dat);
		input_dat += each_main_size; // each_main_size byte

		// XOR _key_beta_v
		input = _mm256_xor_si256(input, *_key_beta_v);
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = _mm256_mullo_epi32(input, *_tb);
			_tb++;
			_out++;
		}

		// XOR and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load
			input = _mm256_loadu_si256((VEC_T *)input_dat);
			input_dat += each_main_size; // each_main_size byte
	
			// XOR _key_beta_v
			input = _mm256_xor_si256(input, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = _mm256_mullo_epi32(input, *_tb);
				*_out = _mm256_add_epi32(tmp, *_out);
				_tb++;
				_out++; 
			}
		}

		// Subtract _prev_c_prime and save output
		for (i = 0; i < HNC_RANK; i++) {
			tmp = _mm256_sub_epi32(output[i], *_prev_c_prime);
			_prev_c_prime++;
			_mm256_storeu_si256((VEC_T *)output_dat, tmp);
			output_dat += each_main_size;
		}
	}

	// Decrypt rem data
	if (rem_size) {
		// Load
		rem_v = _mm256_loadu_si256((VEC_T *)input_dat);

		// Subtract prev_c_prime_0
		tmp =  _mm256_sub_epi32(rem_v, hnc_dat->prev_c_prime_0);

		// XOR _key_beta_v
		rem_v = _mm256_xor_si256(tmp, hnc_dat->key_beta_v_0);

		// Save
		_mm256_storeu_si256((VEC_T *)output_dat, rem_v);
	}

#elif defined(_arm64_)
	if (each_main_size) {
		// Load first 128bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// XOR _key_beta_v
		input0 = veorq_u64(input0, *_key_beta_v);
		_key_beta_v++;

		// Load second 128bit
		input1 = vld1q_u8(input_dat); // 128bit
		input_dat += each_main_size - 16; // Proceed each_main_size byte

		// XOR _key_beta_v
		input1 = veorq_u64(input1, *_key_beta_v);
		_key_beta_v++;

		// Hill Cipher multiplication for i = 0
		_out = output;
		while (_out < output_end) {
			*_out = vmulq_u32(input0, *_tb); // 128bit
			_tb++;
			_out++;
			*_out = vmulq_u32(input1, *_tb); // 128bit
			_tb++;
			_out++;
		}

		// XOR, subtract and Hill Cipher multiplication for i >= 1
		for (i = 1; i < HNC_RANK; i++) {
			// Load first 128bit
			input0 = vld1q_u8(input_dat); // 128bit
			input_dat += 16; // 128bit

			// XOR _key_beta_v
			input0 = veorq_u64(input0, *_key_beta_v);
			_key_beta_v++;

			// Load second 128bit
			input1 = vld1q_u8(input_dat); // 128bit
			input_dat += each_main_size - 16; // Proceed 
							  // each_main_size byte

			// XOR _key_beta_v
			input1 = veorq_u64(input1, *_key_beta_v);
			_key_beta_v++;

			// Hill Cipher multiplication
			_out = output;
			while (_out < output_end) {
				tmp = vmulq_u32(input0, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++;
				tmp = vmulq_u32(input1, *_tb); // 128bit
				*_out = vaddq_u32(tmp, *_out);
				_tb++;
				_out++;
			}
		}

		// Save output
		_out = output;
		for (i = 0; i < HNC_RANK; i++) {
			// Subtract _prev_c_prime
			tmp = vsubq_u32(*_out, *_prev_c_prime);
			_prev_c_prime++;

			// Save
			vst1q_u8(output_dat, tmp); // 128bit
			output_dat += 16; // 128bit
			_out++;

			// Subtract _prev_c_prime
			tmp = vsubq_u32(*_out, *_prev_c_prime);
			_prev_c_prime++;

			// Save
			vst1q_u8(output_dat, tmp); // 128bit
			output_dat += each_main_size - 16; // 128bit
			_out++;
		}
	}

	// Decrypt rem data
	if (rem_size) {
		// Load first 128bit
		input0 = vld1q_u8(input_dat); // 128bit
		input_dat += 16; // 128bit

		// Subtract prev_c_prime_0
		input0 = vsubq_u32(input0, hnc_dat->prev_c_prime_0);

		// XOR _key_beta_v
		rem_v = veorq_u64(input0, hnc_dat->key_beta_v_0);

		// Save 128bit
		vst1q_u8(output_dat, rem_v);
		output_dat += 16;

		// Load second 128bit
		input1 = vld1q_u8(input_dat); // 128bit

		// Subtract prev_c_prime_1
		input1 = vsubq_u32(input1, hnc_dat->prev_c_prime_1);

		// XOR _key_beta_v
		rem_v = veorq_u64(input1, hnc_dat->key_beta_v_1);

		// Save 128bit
		vst1q_u8(output_dat, rem_v);
	}

#endif

	// Copy out_buf to dec_dat
	memcpy(dec_dat, out_buf, dat_siz);
}

#endif // _MOD16_ || _MOD32_

// Encrypt with HNC with padding
void
HNCEncrypt(HNCdatS *hnc_dat, const void *org_dat, void *enc_dat,
	   size_t dat_siz)
{
	lldiv_t	d = lldiv(dat_siz, SIMD_ENCRYPT_SIZE);
	size_t	size = d.quot * SIMD_ENCRYPT_SIZE;

	// Encrypt d.quot * SIMD_ENCRYPT_SIZE byte data with SIMD
	if (size) {
#if defined(_MOD16_) // 16bit
		Mod16EncSIMD(hnc_dat, org_dat, enc_dat, size);
#elif defined(_MOD32_) // 32bit
		Mod32EncSIMD(hnc_dat, org_dat, enc_dat, size);
#endif
	}

	// Encrypt d.rem byte data with SIMD
	if (d.rem) {
#if defined(_MOD16_) // 16bit
		Mod16EncSIMDRem(hnc_dat, org_dat + size,
				enc_dat + size, d.rem);
#elif defined(_MOD32_) // 32bit
		Mod32EncSIMDRem(hnc_dat, org_dat + size,
				enc_dat + size, d.rem);
		//memcpy(enc_dat + size, org_dat + size, d.rem);
#endif
	}
}

// Encrypt with HNC without padding
void
HNCEncryptNoPad(HNCdatS *hnc_dat, const void *org_dat, void *enc_dat,
		size_t dat_siz)
{
	lldiv_t	d = lldiv(dat_siz, SIMD_ENCRYPT_SIZE);
	size_t	size = d.quot * SIMD_ENCRYPT_SIZE;

	// Encrypt d.quot * SIMD_ENCRYPT_SIZE byte data with SIMD
	if (size) {
#if defined(_MOD16_) // 16bit
		Mod16EncSIMD(hnc_dat, org_dat, enc_dat, size);
#elif defined(_MOD32_) // 32bit
		Mod32EncSIMD(hnc_dat, org_dat, enc_dat, size);
#endif
	}

	// Encrypt d.rem byte data with SIMD without padding
	if (d.rem) {
#if defined(_MOD16_) // 16bit
		Mod16EncSIMDRemNoPad(hnc_dat, org_dat + size,
				enc_dat + size, d.rem);
#elif defined(_MOD32_) // 32bit
		Mod32EncSIMDRemNoPad(hnc_dat, org_dat + size,
				enc_dat + size, d.rem);
#endif
	}
}

// Decrypt with HNC with padding
void
HNCDecrypt(HNCdatS *hnc_dat, const void *enc_dat, void *dec_dat,
	   size_t dat_siz)
{
	lldiv_t	d = lldiv(dat_siz, SIMD_ENCRYPT_SIZE);
	size_t	size = d.quot * SIMD_ENCRYPT_SIZE;

	// Decrypt d.quot * SIMD_ENCRYPT_SIZE byte data with SIMD
	if (size) {
#if defined(_MOD16_) // 16bit
		Mod16DecSIMD(hnc_dat, enc_dat, dec_dat, size);
#elif defined(_MOD32_) // 32bit
		Mod32DecSIMD(hnc_dat, enc_dat, dec_dat, size);
#endif
	}

	// Decrypt d.rem byte data with SIMD
	if (d.rem) {
#if defined(_MOD16_) // 16bit
		Mod16DecSIMDRem(hnc_dat, enc_dat + size,
				dec_dat + size, d.rem);
#elif defined(_MOD32_) // 32bit
		Mod32DecSIMDRem(hnc_dat, enc_dat + size,
				dec_dat + size, d.rem);
		//memcpy(dec_dat + size, enc_dat + size, d.rem);
#endif
	}
}

// Decrypt with HNC without padding
void
HNCDecryptNoPad(HNCdatS *hnc_dat, const void *enc_dat, void *dec_dat,
		size_t dat_siz)
{
	lldiv_t	d = lldiv(dat_siz, SIMD_ENCRYPT_SIZE);
	size_t	size = d.quot * SIMD_ENCRYPT_SIZE;

	// Decrypt d.quot * SIMD_ENCRYPT_SIZE byte data with SIMD
	if (size) {
#if defined(_MOD16_) // 16bit
		Mod16DecSIMD(hnc_dat, enc_dat, dec_dat, size);
#elif defined(_MOD32_) // 32bit
		Mod32DecSIMD(hnc_dat, enc_dat, dec_dat, size);
#endif
	}

	// Decrypt d.rem byte data with SIMD
	if (d.rem) {
#if defined(_MOD16_) // 16bit
		Mod16DecSIMDRemNoPad(hnc_dat, enc_dat + size,
				dec_dat + size, d.rem);
#elif defined(_MOD32_) // 32bit
		Mod32DecSIMDRemNoPad(hnc_dat, enc_dat + size,
				dec_dat + size, d.rem);
#endif
	}
}

#if defined(_HNCSL_) // Only hncsl uses these
// Test
static int
Test(HNCdatS *hnc_dat, void *data, void *enc_dat, void *dec_dat)
{
	int		j, err = 0;
	uint64_t	*d = (uint64_t *)data;
	sfmt_t		*sfmt = &hnc_dat->sfmt;
	size_t		dat_siz;

	// Generate random dat
	for (j = 0; j < SEND_DAT_SIZE / sizeof(uint64_t); j++) {
		d[j] = sfmt_genrand_uint64(sfmt);
#if 0	// Debug
		d[j] = j;
#endif
	}


	// Generate random keys and set hnc_dat
	GenHNCkey(hnc_dat);

#if 0	// Try with sample key, not generated one
	//SetSampleHNCkey(hnc_dat);
#endif
	//ShowHNCkey(hnc_dat); // Show keys

	// Decide data size -- Max SEND_DAT_SIZE
	dat_siz = sfmt_genrand_uint64(sfmt) % SEND_DAT_SIZE;
	//dat_siz = 99; // Debug

#if 1
	// Encrypt
	HNCEncrypt(hnc_dat, data, enc_dat, dat_siz);
	//HNCEncryptNoPad(hnc_dat, data, enc_dat, dat_siz);
#else	// You can also save encrypted data to same address as original
	memcpy(enc_dat, data, dat_siz);
	HNCEncrypt(hnc_dat, enc_dat, enc_dat, dat_siz);
	//HNCEncryptNoPad(hnc_dat, enc_dat, enc_dat, dat_siz);
#endif

#if 0	// Debug
	int		k;
	uint16_t	*_o = (uint16_t *)data; 
	uint16_t	*_e = (uint16_t *)enc_dat;
	puts("Enc:");
	for (k = 0; k < 16; k++) {
		printf("%04x %04x\n", _o[k], _e[k]);
	}
#endif

	// Decrypt
	ResetHNCdatCod(hnc_dat); // Reset some parms
#if 1
	HNCDecrypt(hnc_dat, enc_dat, dec_dat, dat_siz);
	//HNCDecryptNoPad(hnc_dat, enc_dat, dec_dat, dat_siz);
#else	// You can also save decrypted data to same address as encrypted
	memcpy(dec_dat, enc_dat, dat_siz);
	HNCDecrypt(hnc_dat, dec_dat, dec_dat, dat_siz);
	//HNCDecryptNoPad(hnc_dat, dec_dat, dec_dat, dat_siz);
#endif

	// Compare
	if (memcmp(data, dec_dat, dat_siz)) {
		int		k;
		size_t		s = (dat_siz / SIMD_ENCRYPT_SIZE) *
					SIMD_ENCRYPT_SIZE;
		uint16_t	*_o = (uint16_t *)data; 
		uint16_t	*_d = (uint16_t *)dec_dat;

		printf("Error: Data don't match (%ldbyte)\n", dat_siz);
		puts("Original Decrypted:");
		for (k = 0; k < 16; k++) {
			printf("%04x %04x\n", _o[s + k - 16], _d[s + k - 16]);
		}
		putchar('\n');
		_o += SIMD_ENCRYPT_SIZE;
		_d += SIMD_ENCRYPT_SIZE;
		for (k = 0; k < 16; k++) {
			//printf("%04x %04x\n", _o[s + k], _d[s + k]);
			//printf("%04x %04x\n", _o[k], _d[k]);

			printf("%04x %04x\n", _o[k], _d[k]);
		}

		err = EPERM;
		goto END;
	}

#if 0
	// Encrypt non SIMD_ENCRYPT_SIZE size data
	uint8_t	tmp_dat[25];

	// Input random numbers to tmp_dat
	for (j = 0; j < sizeof(tmp_dat); j++) {
		tmp_dat[j] = (uint8_t)sfmt_genrand_uint64(sfmt) & 0xff;
#if 0	// Debug
		tmp_dat[j] = j;
#endif
	}

	// Initialize enc_dat, dec_dat
	memset(enc_dat, 0, SIMD_ENCRYPT_SIZE * 2);
	memset(dec_dat, 0, SIMD_ENCRYPT_SIZE * 2);

	// Encrypt
	ResetHNCdatCod(hnc_dat); // Reset some parms
	Mod16EncSIMDRemNoPad(hnc_dat, tmp_dat, enc_dat, sizeof(tmp_dat));

	// Decrypt
	ResetHNCdatCod(hnc_dat); // Reset some parms
	Mod16DecSIMDRemNoPad(hnc_dat, enc_dat, dec_dat, sizeof(tmp_dat));

	// Compare
	if (memcmp(tmp_dat, dec_dat, sizeof(tmp_dat))) {
		int		k;
		uint16_t	*_o = (uint16_t *)data; 
		uint16_t	*_d = (uint16_t *)dec_dat;

		puts("Dec:");
		for (k = 0; k < 16; k++) {
			printf("%04x %04x\n", _o[k], _d[k]);
		}

		puts("Error: Data don't match");
		err = EPERM;
		goto END;
	}
#endif

END:
	return err ? -1 : 0;
}

// Test encoding and decoding
int
HNCTestEncDec(void)
{
	int	i, err = 0;
	void	*data = NULL, *enc_dat = NULL, *dec_dat = NULL;
	HNCdatS	*hnc_dat = NULL;

	// Allocate and initialize hnc_dat
	if ((hnc_dat = AllocHNCdat()) == NULL) {
		Log("Error: AllocHNCdat: %s", strerror(errno));
		err = errno;
		goto END;
	}
	InitHNCdat(hnc_dat);

	// Allocate data
	if ((data = aligned_alloc(32, GEN_DAT_SIZE)) == NULL) {
		Log("Error: %s: aligned_alloc data: %s",
			__func__, strerror(errno));
		err = errno;
		goto END;
	}
	if ((enc_dat = aligned_alloc(32, GEN_DAT_SIZE)) == NULL) {
		Log("Error: %s: aligned_alloc enc_dat: %s",
			__func__, strerror(errno));
		err = errno;
		goto END;
	}
	if ((dec_dat = aligned_alloc(32, GEN_DAT_SIZE)) == NULL) {
		Log("Error: %s: aligned_alloc dec_dat: %s",
			__func__, strerror(errno));
		err = errno;
		goto END;
	}

	// Enc and dec with different data and coef
	for (i = 0; i < 80; i++) {
		//printf("%d\n", i);
		if (Test(hnc_dat, data, enc_dat, dec_dat) == -1) {
			fprintf(stderr, "Info: Test failed at iter %d\n", i);
			err = errno = EPERM;
			goto END;
		}
	}
	puts("Test passed");

END:	// Finalize
	if (hnc_dat != NULL) {
		FreeHNCdat(hnc_dat);
	}
	if (data != NULL) {
		free(data);
	}
	if (enc_dat != NULL) {
		free(enc_dat);
	}
	if (dec_dat != NULL) {
		free(dec_dat);
	}

	return err ? -1 : 0;
}
#endif
