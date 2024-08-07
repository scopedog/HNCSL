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

/******************************************************************************
	This program evaluates the security level of HNC and outputs
	Avalanche Effect, Diffusion and Confusion.
	For Avalanche Effect, the closer to 50% is better and the higher the
	better for Diffusion and Confusion (I guess). 
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#if defined(__FreeBSD__)
#include <libutil.h>
#endif
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#define _MAIN_PROGRAM_
#include "main.h"
#include "common.h"
#include "enc_dec.h"
#include "util.h"
#include "log.h"

/************************************************************
	Functions
************************************************************/

#if 0
// Usage
static void
Usage()
{
	fprintf(stderr, "Usage: %s\n", Program);
	exit(1);
}
#endif

// At exit
static void
AtExit(void)
{
}

// At signal
static void
AtSignal(int sig)
{
	exit(0); // This also calls AtExit()
}

// Initialize 
static void
Init(int argc, char **argv)
{
	char	*p;
	//int	ch;

	// Save arguments
	Argc = argc;
	Argv = argv;

	// Get program name
	if ((p = strrchr(argv[0], '/')) != NULL) {
		p++;
		strncpy(Program, p, sizeof(Program));
	}
	else {
		strncpy(Program, argv[0], sizeof(Program));
	}

        // Get absolute path of program
	realpath(argv[0], ProgramPath);

	// Initialize some parameters
	umask(022); // I don't know if this is good
	Debug = 0;
	Verbose = 0;

#if 0
	// Get option
	while ((ch = getopt(argc, argv, "dhfl:v")) != -1) {
		switch (ch) {
		case 'd': // Debug
			Debug = 1;
			break;
		case 'v': // Verbose
			Verbose = 1;
			break;
		case 'h': // Help
		default:
			Usage();
		}
	}
#endif

	// Register atexit
	atexit(AtExit);

	// Initialize signals
	signal(SIGFPE, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
        signal(SIGKILL, AtSignal);
        signal(SIGINT, AtSignal);
        signal(SIGABRT, AtSignal);
	signal(SIGTERM, AtSignal);
}

// Input random values
static void
Randomize(sfmt_t *sfmt, void *data, size_t size)
{
	uint64_t	*d = (uint64_t *)data;
	size_t		i, num = size / sizeof(uint64_t);

	for (i = 0; i < num; i++) {
		d[i] = sfmt_genrand_uint64(sfmt);
	}
}

// Count # of flipped bits
size_t
CountFlippedBits(void *a, void *b, size_t size)
{
	size_t		i, j, n, count = 0;
	uint64_t	*_a = (uint64_t *)a, *_b = (uint64_t *)b, aa, bb;
	uint64_t	c;

	n = size / 8;
	for (i = 0; i < n; i++) {
		c = 1;
		aa = *_a;
		bb = *_b;
		for (j = 0; j < 64; j++) {
			if ((aa & c) != (bb & c)) {
				count++;
			}
			c <<= 1;
		}
		_a++;
		_b++;
	}

	return count;
}

// Get Avalanche Effect
double
AvalancheEffect(uint64_t *data, uint64_t *enc_dat, size_t size)
{
	size_t	flip_bit = 0;

#if 1
	// Count # of flipped bits
	flip_bit = CountFlippedBits(data, enc_dat, size);
#else
	size_t		i, j, n;
	uint64_t	b, *d = data, *e = enc_dat, _d, _e;

	// Count # of flipped bits
	n = size / sizeof(uint64_t);
	for (i = 0; i < n; i++) {
		b = 1;
		_d = *d;
		_e = *e;
		for (j = 0; j < 64; j++) {
			if ((_d & b) != (_e & b)) {
				flip_bit++;
			}
			b <<= 1;
		}
		d++;
		e++;
	}
#endif

	// Output AE in percentage
	return (double)(flip_bit * 100) / (double)(size * 8);
}

// Get Diffusion
double
Diffusion(HNCdatS *hnc_dat, uint64_t *data, uint64_t *enc_dat)
{
	uint64_t	b, *d = data;
	size_t		i, j, n, flip_bit = 0;
	size_t		_size = SIMD_ENCRYPT_SIZE;
	size_t		size = SIMD_ENCRYPT_SIZE;
 	uint64_t	*org_dat = data + (SEND_DAT_SIZE / 8);
	uint64_t	*enc_dat_1 = enc_dat + (SEND_DAT_SIZE / 8);

	// Input random value to data
	Randomize(&hnc_dat->sfmt, data, size);

	// Encode
	ResetHNCdatCod(hnc_dat);
	HNCEncrypt(hnc_dat, data, enc_dat, size);

	// Back up data
	memcpy(org_dat, data, size);

	// Flip bit of data and compare enc_dat and enc_dat_1
	for (i = 0; i < _size / 8; i++) {
		// Flip bit of data and encode
		b = 1;
		for (j = 0; j < 64; j++) {
			// Restore data
			memcpy(data, org_dat, size);

			// Flip jth bit of data
			*d ^= b;

			// Encode
			ResetHNCdatCod(hnc_dat);
			HNCEncrypt(hnc_dat, data, enc_dat_1, size);

			// Compare enc_dat and enc_dat_1 and count # of
			// flipped bits
			n = CountFlippedBits(enc_dat, enc_dat_1, size);
/*
printf("%ld\n", n);
puts("Data:");
ShowBytes((uint8_t *)data, 64);
puts("enc_dat:");
ShowBytes((uint8_t *)enc_dat, 64);
puts("enc_dat_1:");
ShowBytes((uint8_t *)enc_dat_1, 64);
*/
			flip_bit += n;
			b <<= 1;
		}
		d++;
	}

	// Output Diffusion in percentage
	return (double)(flip_bit * 100) / (double)(size * 8 * size * 8);
}

// Get Confusion
double
Confusion(HNCdatS *hnc_dat, uint64_t *data, uint64_t *enc_dat)
{
	uint8_t	b, *key, *_key;
	uint8_t	*enc_dat_1 = (uint8_t *)enc_dat + SEND_DAT_SIZE;
	size_t	i, j, s, t, n, flip_bit = 0;
	size_t	_size, total_size = 0;
	size_t	size = SEND_DAT_SIZE;
	uint8_t	*org_key;

	// Allocate org_key
	org_key = (uint8_t *)malloc(4 * NUM_BETA_KEYS * HNC_RANK * 64);

	// Input random value to data
	Randomize(&hnc_dat->sfmt, data, size);

	// Encode
	ResetHNCdatCod(hnc_dat);
	HNCEncrypt(hnc_dat, data, enc_dat, size);

	// Flip bit of key_mtrx_enc and compare enc_dat and enc_dat_1
	_size =	sizeof(MOD_T) * HNC_RANK;
	for (s = 0; s < NUM_BETA_KEYS; s++) {
		for (t = 0; t < HNC_RANK; t++) {
			key = _key = (uint8_t *)hnc_dat->key_mtrx_enc[s][t];

			// Back up key_mtrx_enc
			memcpy(org_key, key, _size);

			for (i = 0; i < _size; i++) {
				// Flip bit of key and encode
				b = 1;
				for (j = 0; j < 8; j++) {
					// Flip jth bit of key
					*key ^= b;

					// Encode
					SetHNCdatCod(hnc_dat);
					HNCEncrypt(hnc_dat, data, enc_dat_1,
						size);

					// Compare enc_dat and enc_dat_1 and
					// count # of flipped bits
					n = CountFlippedBits(enc_dat,
							enc_dat_1, size);
					flip_bit += n;
					b <<= 1;

					// Update total_size
					total_size += size;

					// Restore key
					memcpy(_key, org_key, _size);
				}
				key++;
			}
		}
	}

	// Output Confusion in percentage
	return (double)(flip_bit * 100) / (double)(total_size * 8);
}

// Main
int
main(int argc, char **argv)
{
	void		*enc_dat = NULL;
	int		i;
	uint64_t	*data = NULL;
	double		aval_eff, diffusion, confusion;
	HNCdatS		*hnc_dat = NULL;

	// Initialize
	Init(argc, argv);

	// Allocate data
	if ((data = aligned_alloc(32, GEN_DAT_SIZE)) == NULL) {
		Log("Error: %s: aligned_alloc data: %s",
			__func__, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if ((enc_dat = aligned_alloc(32, GEN_DAT_SIZE)) == NULL) {
		Log("Error: %s: aligned_alloc enc_dat: %s",
			__func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Allocate hnc_dat
	if ((hnc_dat = AllocHNCdat()) == NULL) {
		Log("Error: %s: AllocHNCdat: %s", __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}


#if 0 // Debug
	if (HNCTestEncDec() == -1) {
		// Error
		exit(EXIT_FAILURE);
	}
#endif

	// Generate random keys
	GenHNCkey(hnc_dat);

	// Show keys
	//ShowHNCkey(hnc_dat);

#define REPEAT	20
	// Evaluate security
	// Avalanche Effect
	aval_eff = 0.0;
	for (i = 0; i < REPEAT; i++) {
		// Input random value to data
		Randomize(&hnc_dat->sfmt, data, SEND_DAT_SIZE);

		// Encode
		HNCEncrypt(hnc_dat, data, enc_dat, SEND_DAT_SIZE);

		// Calculate average Avalache Effect
		aval_eff += AvalancheEffect(data, enc_dat, SEND_DAT_SIZE);
	}

	// Show average Avalache Effect
	aval_eff /= (double)i;
	printf("Avalache Effect: %.3f%%\n", aval_eff);

	// Diffusion
	diffusion = 0.0;
	for (i = 0; i < 1; i++) {
		// Calculate average Diffusion
		diffusion += Diffusion(hnc_dat, data, enc_dat);
	}

	// Show average Diffusion
	diffusion /= (double)i;
	printf("Diffusion: %.3f%%\n", diffusion);

	// Confusion
	confusion = 0.0;
	for (i = 0; i < 1; i++) {
		// Calculate average Confusion
		confusion += Confusion(hnc_dat, data, enc_dat);
	}

	// Show average Confusion
	confusion /= (double)i;
	printf("Confusion: %.3f%%\n", confusion);

	// Finalize
	if (data != NULL) {
		free(data);
	}
	if (enc_dat != NULL) {
		free(enc_dat);
	}
	if (hnc_dat != NULL) {
		FreeHNCdat(hnc_dat);
	}

	exit(0);
}
