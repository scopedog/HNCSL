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

#ifndef _HNCSL_ENC_DEC_H_
#define _HNCSL_ENC_DEC_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "common.h"
#include "mod.h"
#include "mod_simd.h"
#include "SFMT/SFMT.h"

/*********************************************************************
	Definitions
*********************************************************************/

#define HNC_BUFLEN	1536 // Aligned allocated buffer len


/*********************************************************************
	Structures 
*********************************************************************/

// Data for HNC coding 
typedef struct {
	// Initial prev C' key
	uint8_t		*init_prev_c_prime; // 32 * HNC_RANK
					    // (= SIMD_ENCRYPT_SIZE) byte

	/*********** Common ************/
	// Square key matrices
	MOD_T		*key_mtrx_enc[NUM_MTRX_KEYS][HNC_RANK]; // Enc

	// Inverse of square key matrices
	MOD_T		*key_mtrx_dec[NUM_MTRX_KEYS][HNC_RANK]; // Dec

	// Key beta
	uint8_t		key_beta[NUM_BETA_KEYS][SIMD_ENCRYPT_SIZE];

	/*********** SIMD ************/
	// Key beta
	VEC_T		key_beta_v[NUM_BETA_KEYS]
					[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	// Key beta - first 256bit
#if defined(__AVX2__)
	VEC_T		key_beta_v_0;
#elif defined(_arm64_)
	VEC_T		key_beta_v_0, key_beta_v_1;
#endif

	// Previous C' 
	VEC_T		prev_c_prime[SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];

	// Previous C' - first 256bit
#if defined(__AVX2__)
	VEC_T		prev_c_prime_0;
#elif defined(_arm64_)
	VEC_T		prev_c_prime_0, prev_c_prime_1;
#endif

	// SIMD tables loaded from mod_tb8
#if defined(__AVX2__)
	VEC_T		tb_enc[HNC_RANK * SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
	VEC_T		tb_dec[HNC_RANK * SIMD_ENCRYPT_SIZE / sizeof(VEC_T)];
#elif defined(_arm64_)
#if defined(_MOD16_)
	uint16x8_t	tb_enc[HNC_RANK * SIMD_ENCRYPT_SIZE / 16];
	uint16x8_t	tb_dec[HNC_RANK * SIMD_ENCRYPT_SIZE / 16];
#elif defined(_MOD32_)
	uint32x4_t	tb_enc[HNC_RANK * SIMD_ENCRYPT_SIZE / 16];
	uint32x4_t	tb_dec[HNC_RANK * SIMD_ENCRYPT_SIZE / 16];
#endif
#endif

	// Initialized or not
	bool		inited;

	// Misc
	uint64_t	key_idx; // Key index
	sfmt_t		sfmt; // Random number generator
} HNCdatS;

/*********************************************************************
	Macros
*********************************************************************/

/*********************************************************************
	Functions
*********************************************************************/

HNCdatS	*AllocHNCdat(void); // Allocate HNC dat
void	FreeHNCdat(HNCdatS *); // Free HNC dat
int	InitHNCdat(HNCdatS *); // Initialize HNC dat
void	InitHNCxorKey(HNCdatS *); // Init prev_c_prime with init_prev_c_prime
void	GenHNCinitXorKey(HNCdatS *); // Generate init_prev_c_prime
void	GenHNCcoef(HNCdatS *); // Generate coef
int	SetHNCdatCod(HNCdatS *); // Create coef tables, etc
void	ResetHNCdatCod(HNCdatS *); // Reset some parameters for enc/dec
int	GenHNCkey(HNCdatS *); // Generate keys (init_prev_c_prime and coef)
void	SetSampleHNCkey(HNCdatS *); // Set sample keys from sample-key.h
void	ShowHNCkey(HNCdatS *hnc_dat); // Show keys
void	HNCEncrypt(HNCdatS *, const void *, void *, size_t); // Encrypt with pad
void	HNCEncryptNoPad(HNCdatS *, const void *, void *, size_t);
						// Encrypt without padding
void	HNCDecrypt(HNCdatS *, const void *, void *, size_t); // Decrypt with pad
void	HNCDecryptNoPad(HNCdatS *, const void *, void *, size_t);
						// Decrypt without padding
int	HNCTestEncDec(void); // Test enc & dec


#endif // _HNCSL_ENC_DEC_H_
