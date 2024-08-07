/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2016, 2023
 *      ASUSA Corporation.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/****************************************************************************

	Simple library for modular functions

					Hiroshi Nishida

****************************************************************************/

#include <stdio.h>
#include <stdlib.h> 
#include <stdint.h> 
#include <string.h> 
#include <errno.h> 
#include <time.h> 
#define	_MOD_MAIN_
#include "mod.h"
#undef	_MOD_MAIN_


/**************************************************************************
	8bit
**************************************************************************/

// Initialize 8bit
void
Mod8Init(void)
{
	uint8_t	n, inv, a;

	// Check if already initialized
	if (Mod8Inited) {
		return;
	}
	else {
		Mod8Inited = true;
	}
	
	// Fill Mod8Inv
	for (n = 255; n; n--) {
		for (inv = 255; inv; inv--) {
			Mod8Inv[n] = 0;
			a = n * inv;
			if (a == 1) {
				Mod8Inv[n] = inv;
				break;
			} 
		}
	}
	Mod8Inv[0] = 0;

#if 0	// Debug - Show Mod8Inv
	int	i;
	for (i = 0; i < 256; i++) {
		printf("%d, ", Mod8Inv[i]);
	}
	putchar('\n');
#endif
}

/**************************************************************************
	16bit
**************************************************************************/

// Initialize 16bit
void
Mod16Init(void)
{
	uint16_t	n, inv, a;

	// Check if already initialized
	if (Mod16Inited) {
		return;
	}
	else {
		Mod16Inited = true;
	}
	
	// Fill Mod16Inv
	for (n = 65535; n; n--) {
		for (inv = 65535; inv; inv--) {
			Mod16Inv[n] = 0;
			a = n * inv;
			if (a == 1) {
				Mod16Inv[n] = inv;
				break;
			} 
		}
	}
	Mod16Inv[0] = 0;

#if 0	// Debug - Show Mod16Inv
	int	i;
	for (i = 0; i < 65536; i++) {
		printf("%d, ", Mod16Inv[i]);
	}
	putchar('\n');
#endif
}

/**************************************************************************
	32bit
**************************************************************************/

#define BIT_32	(1LL << 32LL)

// C program to find multiplicative modulo inverse using 
// Extended Euclid algorithm. 
static int
gcdExtended32(uint32_t a, uint64_t b, uint32_t *x, uint32_t *y) 
{ 
	// Base Case 
	if (a == 0) { 
		*x = 0, *y = 1; 
		return b; 
	} 
  
	uint32_t	x1, y1; // To store results of recursive call 
	int		gcd = gcdExtended32(b % a, (uint64_t)a, &x1, &y1); 
  
	// Update x and y using results of recursive call 
	*x = y1 - (b / a) * x1; 
	*y = x1; 
  
	return gcd; 
}
  
// Function to find modulo inverse of a 
uint32_t
Mod32Inv(uint32_t A) 
{ 
	uint64_t	M = 1LL << 32;
	uint32_t	x, y; 

	return gcdExtended32(A, M, &x, &y) == 1 ? (x % M + M) % M : 0;
} 

// Test Mod32Inv()
int
Mod32TestInv(void)
{
	int		i, repeat = 2000;
	uint32_t	a32, inv32, tmp32;

	// Initialize
	srand(time(NULL));

	// Test Mod32Inv()
	puts("Testing Mod32 inverse:");
	for (i = 0; i < repeat; i++) {
		a32 = rand() & 0xffffffff;

		// Check invertibility
		if (!Mod32Invertible(a32)) { // Not invertible
			continue;
		}

		// Get inverse
		inv32 = Mod32Inv(a32);

		// Check
		tmp32 = a32 * inv32;
		if (tmp32 != 1) {
			fprintf(stderr, "Error: Test failed at iter %d\n", i);
			break;
		}
	}

	if (i == repeat) {
		puts("  Test passed");
		return 0;
	}
	else {
		puts("  Test failed");
		return -1;
	}
}
