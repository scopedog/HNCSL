/**************************************************************************

		Functions for matrices in Modular

**************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include "mod.h"

/**************************************************************************
		8bit
**************************************************************************/

// Multiply N * N matrix and N vector y = A * x
void
Mod8MtrxByVct(uint8_t **A, uint8_t *x, uint8_t *y, int N)
{
	int	i, j;
	uint8_t	*a, *_x, tmp;

	for (i = 0; i < N; i++) {
		a = A[i];
		_x = x;
		tmp = a[0] * *_x;
		for (j = 1; j < N; j++) {
			_x++;
			tmp += a[j] * *_x;
		}
		y[i] = tmp;
	}
}

// Multiply two N * N matrices: C = A * B
void
Mod8MtrxByMtrx(uint8_t **A, uint8_t **B, uint8_t **C, int N)
{
	int	i, j, k;
	uint8_t	*a, *c, tmp;

	for (i = 0; i < N; i++) {
		a = A[i];
		c = C[i];
		for (j = 0; j < N; j++) {
			tmp = a[0] * B[0][j];
			for (k = 1; k < N; k++) {
				tmp += a[k] * B[k][j];
			}
			c[j] = tmp;
		}
	}
}

// Calculate determinant
static uint8_t
Mod8Determinant(uint8_t **A, int m_size)
{
	uint8_t	s = 1, det = 0, *tmp[MAX_MOD_MTRX_SIZE];
	int	i, j, m, n, c;

	// Allocate tmp
	for (i = 0; i < m_size; i++) {
		tmp[i] = alloca(sizeof(uint8_t) * m_size);
	}

	if (m_size == 1) {
		return A[0][0];
	}

	det = 0;
	for (c = 0; c < m_size; c++) {
		m = 0;
		n = 0;
		for (i = 0; i < m_size; i++) {
			for (j = 0; j < m_size; j++) {
				tmp[i][j] = 0;
				if (i != 0 && j != c) {
					tmp[m][n] = A[i][j];
					if (n < (m_size - 2)) {
						n++;
					}
					else {
						n = 0;
						m++;
					}
				}
			}
		}

		// Recursively calculate determinat for tmp matrix
		det += s * (A[0][c] * Mod8Determinant(tmp, m_size - 1));
		s = -s;
	}

	return det;
}

// Transpose
static void
Mod8Transpose(uint8_t **A, uint8_t **fac, uint8_t **invA, int m_size,
	  uint8_t det)
{
	int	i, j;

	// We assume det is invertible
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			// Transpose and divide by det
			invA[i][j] = Mod8Div(fac[j][i], det);
		}
	}

#if 0	// Debug
	uint8_t	*tmp[MAX_MOD_MTRX_SIZE];

	for (i = 0; i < m_size; i++) {
		tmp[i] = alloca(sizeof(uint8_t) * m_size);
	}

	printf("\nThe inverse of matrix is : \n");

	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			printf("\t%d", invA[i][j]);
		}
		printf("\n");
	}

	Mod8MtrxByMtrx(A, invA, tmp, m_size);
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			printf("\t%d", tmp[i][j]);
		}
		putchar('\n');
	}
	putchar('\n');

	uint8_t	*test[MAX_MOD_MTRX_SIZE], _tmp;
	for (i = 0; i < m_size; i++) {
		test[i] = malloc(sizeof(uint8_t) * m_size);
		for (j = 0; j < m_size; j++) {
			_tmp = (uint8_t)((rand() >> 3) & 0xff);
			test[i][j] = _tmp;
			printf("\t%d", _tmp);
		}
		putchar('\n');
	}
	putchar('\n');

	Mod8MtrxByMtrx(A, test, tmp, m_size);
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			test[i][j] = tmp[i][j];
			printf("\t%d", test[i][j]);
		}
		putchar('\n');
	}
	putchar('\n');
	Mod8MtrxByMtrx(invA, tmp, test, m_size);
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			printf("\t%d", test[i][j]);
		}
		putchar('\n');
	}
#endif
}

// Invert
static void
Mod8Invert(uint8_t **A, uint8_t **invA, int m_size, uint8_t det)
{
	int	p, q, m, n, i, j;
	uint8_t	*tmp[MAX_MOD_MTRX_SIZE], *fac[MAX_MOD_MTRX_SIZE], d;

	// Allocate tmp, fac
	for (i = 0; i < m_size; i++) {
		tmp[i] = alloca(sizeof(uint8_t) * m_size);
		fac[i] = alloca(sizeof(uint8_t) * m_size);
	}

	for (q = 0; q < m_size; q++) {
		for (p = 0; p < m_size; p++) {
			m = 0;
			n = 0;
			for (i = 0; i < m_size; i++) {
				for (j = 0; j < m_size; j++) {
					if (i != q && j != p) {
						tmp[m][n] = A[i][j];
						if (n < (m_size - 2)) {
							n++;
						}
						else {
							n = 0;
							m++;
						}
					}
				}
			}

			//fac[q][p] = pow(-1, q + p) * Mod8Determinant(tmp, m_size - 1);
			d = Mod8Determinant(tmp, m_size - 1);
			if (((q + p) & 1)) {
				d = -d;
			}
			fac[q][p] = d;
		}
	}

#if 0	// Debug
	puts("fac:");
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			printf("%d ", fac[i][j]);
		}
		putchar('\n');
	}
	putchar('\n');
#endif

	// Transpose
	Mod8Transpose(A, fac, invA, m_size, det);
}

// Invert matrix
int
Mod8InvMtrx(uint8_t **A, uint8_t **invA, int N)
{
	uint8_t	det;

	// Get determinant first
	det = Mod8Determinant(A, N);

	// Check if det is invertible
	if (Mod8Invertible(det)) {
		// Invert by calculating cofactors and trandposing
		Mod8Invert(A, invA, N, det); // Invert
		return 0;
	}
	else {
		//puts("Not invertible");
		return -1;
	}
}

// Test
static int
Mod8Test(uint8_t **A, uint8_t **invA, uint8_t **C)
{
	int	i, j, mtrx_size;
	uint8_t	det, *c;

	// Determine mtrx_size
	mtrx_size = (rand() % 6) + 3; // 3-8

	// Determine A
	for (i = 0; i < mtrx_size; i++) {
		for (j = 0; j < mtrx_size; j++) {
			A[i][j] = (uint8_t)(rand() & 0xff);
		}
	}

	// Get determinant and check if it's invertible
	det = Mod8Determinant(A, mtrx_size);
	if (!Mod8Invertible(det)) {
		//printf("Info: determinant %d is not invertible\n", det);
		return 1;
	}

	// Get inverse of matrix
	Mod8Invert(A, invA, mtrx_size, det);

	// Multiply A and invA, result C is supposed to be I
	Mod8MtrxByMtrx(A, invA, C, mtrx_size);

#if 0
	// Show result
	putchar('\n');
	puts("A:");
	for (i = 0; i < mtrx_size; i++) {
		for (j = 0; j < mtrx_size; j++) {
			printf("%d ", A[i][j]);
		}
		putchar('\n');
	}
	putchar('\n');

	puts("invA:");
	for (i = 0; i < mtrx_size; i++) {
		for (j = 0; j < mtrx_size; j++) {
			printf("%d ", invA[i][j]);
		}
		putchar('\n');
	}
	putchar('\n');

	puts("A * invA:");
	for (i = 0; i < mtrx_size; i++) {
		for (j = 0; j < mtrx_size; j++) {
			printf("%d ", C[i][j]);
		}
		putchar('\n');
	}
#endif

	// Check if C == I
	for (i = 0; i < mtrx_size; i++) {
		c = C[i];
		for (j = 0; j < mtrx_size; j++) {
			if (i == j) {
				if (c[i] != 1) {
					fprintf(stderr, "Error: "
						"C[%d][%d] = %d (!= 1)\n",
						i, i, c[i]);
					errno = EPERM;
					return -1;
				}
			}
			else if (c[j] != 0) {
				fprintf(stderr, "Error: C[%d][%d] = %d "
					"(!= 0)\n", i, j, c[j]);
				errno = EPERM;
				return -1;
			}
		}
	}

	return 0;
}

// Test matrix
int
Mod8TestMtrx(void)
{
	int	i, non_det_count, ret, repeat = 2000;
	uint8_t	*A[MAX_MOD_MTRX_SIZE], *invA[MAX_MOD_MTRX_SIZE];
	uint8_t	*C[MAX_MOD_MTRX_SIZE];

	// Initialize
	Mod8Init();

	srand(time(NULL));
	for (i = 0; i < MAX_MOD_MTRX_SIZE; i++) {
		A[i] = malloc(sizeof(uint8_t) * MAX_MOD_MTRX_SIZE);
		invA[i] = malloc(sizeof(uint8_t) * MAX_MOD_MTRX_SIZE);
		C[i] = malloc(sizeof(uint8_t) * MAX_MOD_MTRX_SIZE);
	}

	// Test Mod8
	puts("Testing Mod8 matrix features:");
	non_det_count = 0;
	for (i = 0; i < repeat; i++) {
		//printf("%d\n", i);
		switch (Mod8Test(A, invA, C)) {
		case -1: // Failed
			fprintf(stderr, "Error: Test failed at iter %d\n", i);
			goto LOOP_EXIT;
		case 1: // Not invertible
			non_det_count++;
			break;
		case 0: // Passed
			break;
		default:
			break;
		}
	}

LOOP_EXIT:
	// 
	if (i == repeat) {
		puts("  Test passed");
		ret = 0;
	}
	else {
		puts("  Test failed");
		ret = -1;
	}

	// Print # of non-invertible matrices
	printf("  %d out of %d (%f%%) were non-invertible\n",
		non_det_count, repeat,
		(float)(non_det_count * 100) / (float)repeat);

	// Finalize
	for (i = 0; i < MAX_MOD_MTRX_SIZE; i++) {
		free(A[i]);
		free(invA[i]);
		free(C[i]);
	}
	
	return ret;
}

/**************************************************************************
		16bit
**************************************************************************/

#if 0
// Show array
static void
ShowArray16(uint16_t *a, int N)
{
	int	i;

	for (i = 0; i < N; i++) {
		printf("%d ", a[i]);
	}
	putchar('\n');
}
#endif

// Multiply N * N matrix and N vector y = A * x
void
Mod16MtrxByVct(uint16_t **A, uint16_t *x, uint16_t *y, int N)
{
	int		i, j;
	uint16_t	*a, *_x, tmp;

	for (i = 0; i < N; i++) {
		a = A[i];
		_x = x;
		tmp = a[0] * *_x;
		for (j = 1; j < N; j++) {
			_x++;
			tmp += a[j] * *_x;
		}
		y[i] = tmp;
	}
}

// Multiply two N * N matrices: C = A * B
void
Mod16MtrxByMtrx(uint16_t **A, uint16_t **B, uint16_t **C, int N)
{
	int		i, j, k;
	uint16_t	*a, *c, tmp;

	for (i = 0; i < N; i++) {
		a = A[i];
		c = C[i];
		for (j = 0; j < N; j++) {
			tmp = a[0] * B[0][j];
			for (k = 1; k < N; k++) {
				tmp += a[k] * B[k][j];
			}
			c[j] = tmp;
		}
	}
}

// Calculate determinant
static uint16_t
Mod16Determinant(uint16_t **A, int m_size)
{
	uint16_t	s = 1, det = 0, *tmp[MAX_MOD_MTRX_SIZE];
	int		i, j, m, n, c;

	// Allocate tmp
	for (i = 0; i < m_size; i++) {
		tmp[i] = alloca(sizeof(uint16_t) * m_size);
	}

	if (m_size == 1) {
		return A[0][0];
	}

	det = 0;
	for (c = 0; c < m_size; c++) {
		m = 0;
		n = 0;
		for (i = 0; i < m_size; i++) {
			for (j = 0; j < m_size; j++) {
				tmp[i][j] = 0;
				if (i != 0 && j != c) {
					tmp[m][n] = A[i][j];
					if (n < (m_size - 2)) {
						n++;
					}
					else {
						n = 0;
						m++;
					}
				}
			}
		}

		// Recursively calculate determinat for tmp matrix
		det += s * (A[0][c] * Mod16Determinant(tmp, m_size - 1));
		s = -s;
	}

	return det;
}

// Transpose
static void
Mod16Transpose(uint16_t **A, uint16_t **fac, uint16_t **invA, int m_size,
	  uint16_t det)
{
	int		i, j;

	// We assume det is invertible
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			// Transpose and divide by det
			invA[i][j] = Mod16Div(fac[j][i], det);
		}
	}

#if 0	// Debug
	uint16_t	*tmp[MAX_MOD_MTRX_SIZE];

	for (i = 0; i < m_size; i++) {
		tmp[i] = alloca(sizeof(uint16_t) * m_size);
	}

	printf("\nThe inverse of matrix is : \n");

	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			printf("\t%d", inv[i][j]);
		}
		printf("\n");
	}

	Mod16MtrxByMtrx(A, inv, tmp, m_size);
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			printf("\t%d", tmp[i][j]);
		}
		putchar('\n');
	}
	putchar('\n');

	uint16_t	*test[MAX_MOD_MTRX_SIZE], _tmp;
	for (i = 0; i < m_size; i++) {
		test[i] = malloc(sizeof(uint16_t) * m_size);
		for (j = 0; j < m_size; j++) {
			_tmp = (uint16_t)(rand() & 0xffff);
			test[i][j] = _tmp;
			printf("\t%d", _tmp);
		}
		putchar('\n');
	}
	putchar('\n');

	Mod16MtrxByMtrx(A, test, tmp, m_size);
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			test[i][j] = tmp[i][j];
			printf("\t%d", test[i][j]);
		}
		putchar('\n');
	}
	putchar('\n');
	Mod16MtrxByMtrx(inv, tmp, test, m_size);
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			printf("\t%d", test[i][j]);
		}
		putchar('\n');
	}
#endif
}

// Invert
static void
Mod16Invert(uint16_t **A, uint16_t **invA, int m_size, uint16_t det)
{
	int		p, q, m, n, i, j;
	uint16_t	*tmp[MAX_MOD_MTRX_SIZE], *fac[MAX_MOD_MTRX_SIZE], d;

	// Allocate tmp, fac
	for (i = 0; i < m_size; i++) {
		tmp[i] = alloca(sizeof(uint16_t) * m_size);
		fac[i] = alloca(sizeof(uint16_t) * m_size);
	}

	for (q = 0; q < m_size; q++) {
		for (p = 0; p < m_size; p++) {
			m = 0;
			n = 0;
			for (i = 0; i < m_size; i++) {
				for (j = 0; j < m_size; j++) {
					if (i != q && j != p) {
						tmp[m][n] = A[i][j];
						if (n < (m_size - 2)) {
							n++;
						}
						else {
							n = 0;
							m++;
						}
					}
				}
			}

			//fac[q][p] = pow(-1, q + p) * Mod16Determinant(tmp, m_size - 1);
			d = Mod16Determinant(tmp, m_size - 1);
			if (((q + p) & 1)) {
				d = -d;
			}
			fac[q][p] = d;
		}
	}

	// Transpose
	Mod16Transpose(A, fac, invA, m_size, det);
}

// Invert matrix
int
Mod16InvMtrx(uint16_t **A, uint16_t **invA, int N)
{
	uint16_t	det;

	// Get determinant first
	det = Mod16Determinant(A, N);

	// Check if det is invertible
	if (Mod16Invertible(det)) {
		// Invert by calculating cofactors and trandposing
		Mod16Invert(A, invA, N, det); // Invert
		return 0;
	}
	else {
		//puts("Not invertible");
		return -1;
	}
}

// Show 3 * 3 matrix
void
Mod16ShowMtrx3(uint16_t (*A)[3])
{
	int	i, j;

	for (i = 0; i < 3; i++) {
		for (j = 0; j < 3; j++) {
			printf("%04x ", A[i][j]);
		}
		putchar('\n');
	}
	putchar('\n');
}

// Multiply 3 * 3 matrix and 3 vector y = A * x
void
Mod16MtrxByVct3(uint16_t (*A)[3], uint16_t *x, uint16_t *y)
{
	int		i, j;
	uint16_t	*a, *_x, tmp;

	for (i = 0; i < 3; i++) {
		a = A[i];
		_x = x;
		tmp = a[0] * *_x;
		for (j = 1; j < 3; j++) {
			_x++;
			tmp += a[j] * *_x;
		}
		y[i] = tmp;
	}
}

// Multiply two 3 * 3 matrices: C = A * B
void
Mod16MtrxByMtrx3(uint16_t (*A)[3], uint16_t (*B)[3], uint16_t (*C)[3])
{
	int		i, j, k;
	uint16_t	*a, *c, tmp;

	for (i = 0; i < 3; i++) {
		a = A[i];
		c = C[i];
		for (j = 0; j < 3; j++) {
			tmp = a[0] * B[0][j];
			for (k = 1; k < 3; k++) {
				tmp += a[k] * B[k][j];
			}
			c[j] = tmp;
		}
	}
}

// Invert 3x3 matrix
int
Mod16InvMtrx3(uint16_t (*A)[3], uint16_t (*invA)[3])
{
	uint16_t	a = A[0][0], b = A[0][1], c = A[0][2];
	uint16_t	d = A[0][0], e = A[0][1], f = A[0][2];
	uint16_t	g = A[0][0], h = A[0][1], i = A[0][2];
	uint16_t	det, det_inv;

	// Get determinant
	det = (a * e * i) - (a * f * h) - (b * d * i) +
	      (b * f * g) + (c * d * h) - (c * e * g);

	// Check if det is invertible
	if (!Mod16Invertible(det)) {
		//printf("Info: determinant %d is not invertible\n", det);
		return -1;
	}
 
	// Get inverse
	det_inv = Mod16Inv[det];
	invA[0][0] = ((e * i) - (f * h)) * det_inv;  
	invA[0][1] = ((c * h) - (b * i)) * det_inv;  
	invA[0][2] = ((b * f) - (c * e)) * det_inv;  
	invA[1][0] = ((f * g) - (d * i)) * det_inv;  
	invA[1][1] = ((a * i) - (c * g)) * det_inv;  
	invA[1][2] = ((c * d) - (a * f)) * det_inv;  
	invA[2][0] = ((d * h) - (e * g)) * det_inv;  
	invA[2][1] = ((b * g) - (a * h)) * det_inv;  
	invA[2][2] = ((a * e) - (b * d)) * det_inv;  
 
	return 0;
}

// Test
static int
Mod16Test(uint16_t **A, uint16_t **invA, uint16_t **C)
{
	int		i, j, mtrx_size;
	uint16_t	det, *c;

	// Determine mtrx_size
	mtrx_size = (rand() % 6) + 3; // 3-8

	// Determine A
	for (i = 0; i < mtrx_size; i++) {
		for (j = 0; j < mtrx_size; j++) {
			A[i][j] = (uint16_t)(rand() & 0xffff);
		}
	}

	// Get determinant and check if it's invertible
	det = Mod16Determinant(A, mtrx_size);
	if (!Mod16Invertible(det)) {
		//printf("Info: determinant %d is not invertible\n", det);
		return 1;
	}
	//printf("det = %d\n", det);

	// Get inverse of matrix
	Mod16Invert(A, invA, mtrx_size, det);

	// Multiply A and invA, result C is supposed to be I
	Mod16MtrxByMtrx(A, invA, C, mtrx_size);

#if 0
	// Show result
	putchar('\n');
	for (i = 0; i < mtrx_size; i++) {
		for (j = 0; j < mtrx_size; j++) {
			printf("%d ", A[i][j]);
		}
		putchar('\n');
	}

	putchar('\n');
	for (i = 0; i < mtrx_size; i++) {
		for (j = 0; j < mtrx_size; j++) {
			printf("%d ", C[i][j]);
		}
		putchar('\n');
	}
#endif

	// Check if C == I
	for (i = 0; i < mtrx_size; i++) {
		c = C[i];
		for (j = 0; j < mtrx_size; j++) {
			if (i == j) {
				if (c[i] != 1) {
					fprintf(stderr, "Error: "
						"C[%d][%d] = %d (!= 1)\n",
						i, i, c[i]);
					errno = EPERM;
					return -1;
				}
			}
			else if (c[j] != 0) {
				fprintf(stderr, "Error: C[%d][%d] = %d "
					"(!= 0)\n", i, j, c[j]);
				errno = EPERM;
				return -1;
			}
		}
	}

	return 0;
}

// Test matrix
int
Mod16TestMtrx(void)
{
	int		i, non_det_count, ret, repeat = 2000;
	uint16_t	*A[MAX_MOD_MTRX_SIZE], *invA[MAX_MOD_MTRX_SIZE];
	uint16_t	*C[MAX_MOD_MTRX_SIZE];

	// Initialize
	Mod16Init();

	srand(time(NULL));
	for (i = 0; i < MAX_MOD_MTRX_SIZE; i++) {
		A[i] = malloc(sizeof(uint16_t) * MAX_MOD_MTRX_SIZE);
		invA[i] = malloc(sizeof(uint16_t) * MAX_MOD_MTRX_SIZE);
		C[i] = malloc(sizeof(uint16_t) * MAX_MOD_MTRX_SIZE);
	}

	// Test Mod16
	puts("Testing Mod16 matrix features:");
	non_det_count = 0;
	for (i = 0; i < repeat; i++) {
		//printf("%d\n", i);
		switch (Mod16Test(A, invA, C)) {
		case -1: // Failed
			fprintf(stderr, "Error: Test failed at iter %d\n", i);
			goto LOOP_EXIT;
		case 1: // Not invertible
			non_det_count++;
			break;
		case 0: // Passed
			break;
		default:
			break;
		}
	}

LOOP_EXIT:
	// 
	if (i == repeat) {
		puts("  Test passed");
		ret = 0;
	}
	else {
		puts("  Test failed");
		ret = -1;
	}

	// Print # of non-invertible matrices
	printf("  %d out of %d (%f%%) were non-invertible\n",
		non_det_count, repeat,
		(float)(non_det_count * 100) / (float)repeat);

	// Finalize
	for (i = 0; i < MAX_MOD_MTRX_SIZE; i++) {
		free(A[i]);
		free(invA[i]);
		free(C[i]);
	}
	
	return ret;
}


/**************************************************************************
		32bit
**************************************************************************/

#if 0
// Show array
static void
ShowArray32(uint32_t *a, int N)
{
	int	i;

	for (i = 0; i < N; i++) {
		printf("%d ", a[i]);
	}
	putchar('\n');
}
#endif

// Multiply N * N matrix and N vector y = A * x
void
Mod32MtrxByVct(uint32_t **A, uint32_t *x, uint32_t *y, int N)
{
	int		i, j;
	uint32_t	*a, *_x, tmp;

	for (i = 0; i < N; i++) {
		a = A[i];
		_x = x;
		tmp = a[0] * *_x;
		for (j = 1; j < N; j++) {
			_x++;
			tmp += a[j] * *_x;
		}
		y[i] = tmp;
	}
}

// Multiply two N * N matrices: C = A * B
void
Mod32MtrxByMtrx(uint32_t **A, uint32_t **B, uint32_t **C, int N)
{
	int		i, j, k;
	uint32_t	*a, *c, tmp;

	for (i = 0; i < N; i++) {
		a = A[i];
		c = C[i];
		for (j = 0; j < N; j++) {
			tmp = a[0] * B[0][j];
			for (k = 1; k < N; k++) {
				tmp += a[k] * B[k][j];
			}
			c[j] = tmp;
		}
	}
}

// Calculate determinant
static uint32_t
Mod32Determinant(uint32_t **A, int m_size)
{
	uint32_t	s = 1, det = 0, *tmp[MAX_MOD_MTRX_SIZE];
	int		i, j, m, n, c;

	// Allocate tmp
	for (i = 0; i < m_size; i++) {
		tmp[i] = alloca(sizeof(uint32_t) * m_size);
	}

	if (m_size == 1) {
		return A[0][0];
	}

	det = 0;
	for (c = 0; c < m_size; c++) {
		m = 0;
		n = 0;
		for (i = 0; i < m_size; i++) {
			for (j = 0; j < m_size; j++) {
				tmp[i][j] = 0;
				if (i != 0 && j != c) {
					tmp[m][n] = A[i][j];
					if (n < (m_size - 2)) {
						n++;
					}
					else {
						n = 0;
						m++;
					}
				}
			}
		}

		// Recursively calculate determinat for tmp matrix
		det += s * (A[0][c] * Mod32Determinant(tmp, m_size - 1));
		s = -s;
	}

	return det;
}

// Transpose
static void
Mod32Transpose(uint32_t **A, uint32_t **fac, uint32_t **invA, int m_size,
	  uint32_t det)
{
	int		i, j;

	// We assume det is invertible
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			// Transpose and divide by det
			invA[i][j] = Mod32Div(fac[j][i], det);
		}
	}

#if 0	// Debug
	uint32_t	*tmp[MAX_MOD_MTRX_SIZE];

	for (i = 0; i < m_size; i++) {
		tmp[i] = alloca(sizeof(uint32_t) * m_size);
	}

	printf("\nThe inverse of matrix is : \n");

	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			printf("\t%d", inv[i][j]);
		}
		printf("\n");
	}

	Mod32MtrxByMtrx(A, inv, tmp, m_size);
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			printf("\t%d", tmp[i][j]);
		}
		putchar('\n');
	}
	putchar('\n');

	uint32_t	*test[MAX_MOD_MTRX_SIZE], _tmp;
	for (i = 0; i < m_size; i++) {
		test[i] = malloc(sizeof(uint32_t) * m_size);
		for (j = 0; j < m_size; j++) {
			_tmp = (uint32_t)(rand() & 0xffff);
			test[i][j] = _tmp;
			printf("\t%d", _tmp);
		}
		putchar('\n');
	}
	putchar('\n');

	Mod32MtrxByMtrx(A, test, tmp, m_size);
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			test[i][j] = tmp[i][j];
			printf("\t%d", test[i][j]);
		}
		putchar('\n');
	}
	putchar('\n');
	Mod32MtrxByMtrx(inv, tmp, test, m_size);
	for (i = 0; i < m_size; i++) {
		for (j = 0; j < m_size; j++) {
			printf("\t%d", test[i][j]);
		}
		putchar('\n');
	}
#endif
}

// Invert
static void
Mod32Invert(uint32_t **A, uint32_t **invA, int m_size, uint32_t det)
{
	int		p, q, m, n, i, j;
	uint32_t	*tmp[MAX_MOD_MTRX_SIZE], *fac[MAX_MOD_MTRX_SIZE], d;

	// Allocate tmp, fac
	for (i = 0; i < m_size; i++) {
		tmp[i] = alloca(sizeof(uint32_t) * m_size);
		fac[i] = alloca(sizeof(uint32_t) * m_size);
	}

	for (q = 0; q < m_size; q++) {
		for (p = 0; p < m_size; p++) {
			m = 0;
			n = 0;
			for (i = 0; i < m_size; i++) {
				for (j = 0; j < m_size; j++) {
					if (i != q && j != p) {
						tmp[m][n] = A[i][j];
						if (n < (m_size - 2)) {
							n++;
						}
						else {
							n = 0;
							m++;
						}
					}
				}
			}

			//fac[q][p] = pow(-1, q + p) * Mod32Determinant(tmp, m_size - 1);
			d = Mod32Determinant(tmp, m_size - 1);
			if (((q + p) & 1)) {
				d = -d;
			}
			fac[q][p] = d;
		}
	}

	// Transpose
	Mod32Transpose(A, fac, invA, m_size, det);
}

// Invert matrix
int
Mod32InvMtrx(uint32_t **A, uint32_t **invA, int N)
{
	uint32_t	det;

	// Get determinant first
	det = Mod32Determinant(A, N);

	// Check if det is invertible
	if (Mod32Invertible(det)) {
		// Invert by calculating cofactors and trandposing
		Mod32Invert(A, invA, N, det); // Invert
		return 0;
	}
	else {
		//puts("Not invertible");
		return -1;
	}
}

// Show 3 * 3 matrix
void
Mod32ShowMtrx3(uint32_t (*A)[3])
{
	int	i, j;

	for (i = 0; i < 3; i++) {
		for (j = 0; j < 3; j++) {
			printf("%04x ", A[i][j]);
		}
		putchar('\n');
	}
	putchar('\n');
}

// Multiply 3 * 3 matrix and 3 vector y = A * x
void
Mod32MtrxByVct3(uint32_t (*A)[3], uint32_t *x, uint32_t *y)
{
	int		i, j;
	uint32_t	*a, *_x, tmp;

	for (i = 0; i < 3; i++) {
		a = A[i];
		_x = x;
		tmp = a[0] * *_x;
		for (j = 1; j < 3; j++) {
			_x++;
			tmp += a[j] * *_x;
		}
		y[i] = tmp;
	}
}

// Multiply two 3 * 3 matrices: C = A * B
void
Mod32MtrxByMtrx3(uint32_t (*A)[3], uint32_t (*B)[3], uint32_t (*C)[3])
{
	int		i, j, k;
	uint32_t	*a, *c, tmp;

	for (i = 0; i < 3; i++) {
		a = A[i];
		c = C[i];
		for (j = 0; j < 3; j++) {
			tmp = a[0] * B[0][j];
			for (k = 1; k < 3; k++) {
				tmp += a[k] * B[k][j];
			}
			c[j] = tmp;
		}
	}
}

// Invert 3x3 matrix
int
Mod32InvMtrx3(uint32_t (*A)[3], uint32_t (*invA)[3])
{
	uint32_t	a = A[0][0], b = A[0][1], c = A[0][2];
	uint32_t	d = A[0][0], e = A[0][1], f = A[0][2];
	uint32_t	g = A[0][0], h = A[0][1], i = A[0][2];
	uint32_t	det, det_inv;

	// Get determinant
	det = (a * e * i) - (a * f * h) - (b * d * i) +
	      (b * f * g) + (c * d * h) - (c * e * g);

	// Check if det is invertible
	if (!Mod32Invertible(det)) {
		//printf("Info: determinant %d is not invertible\n", det);
		return -1;
	}
 
	// Get inverse
	det_inv = Mod32Inv(det);
	invA[0][0] = ((e * i) - (f * h)) * det_inv;  
	invA[0][1] = ((c * h) - (b * i)) * det_inv;  
	invA[0][2] = ((b * f) - (c * e)) * det_inv;  
	invA[1][0] = ((f * g) - (d * i)) * det_inv;  
	invA[1][1] = ((a * i) - (c * g)) * det_inv;  
	invA[1][2] = ((c * d) - (a * f)) * det_inv;  
	invA[2][0] = ((d * h) - (e * g)) * det_inv;  
	invA[2][1] = ((b * g) - (a * h)) * det_inv;  
	invA[2][2] = ((a * e) - (b * d)) * det_inv;  
 
	return 0;
}

// Test
static int
Mod32Test(uint32_t **A, uint32_t **invA, uint32_t **C)
{
	int		i, j, mtrx_size;
	uint32_t	det, *c;

	// Determine mtrx_size
	mtrx_size = (rand() % 6) + 3; // 3-8

	// Determine A
	for (i = 0; i < mtrx_size; i++) {
		for (j = 0; j < mtrx_size; j++) {
			A[i][j] = (uint32_t)(rand() & 0xffff);
		}
	}

	// Get determinant and check if it's invertible
	det = Mod32Determinant(A, mtrx_size);
	if (!Mod32Invertible(det)) {
		//printf("Info: determinant %d is not invertible\n", det);
		return 1;
	}
	//printf("det = %d\n", det);

	// Get inverse of matrix
	Mod32Invert(A, invA, mtrx_size, det);

	// Multiply A and invA, result C is supposed to be I
	Mod32MtrxByMtrx(A, invA, C, mtrx_size);

#if 0
	// Show result
	putchar('\n');
	for (i = 0; i < mtrx_size; i++) {
		for (j = 0; j < mtrx_size; j++) {
			printf("%d ", A[i][j]);
		}
		putchar('\n');
	}

	putchar('\n');
	for (i = 0; i < mtrx_size; i++) {
		for (j = 0; j < mtrx_size; j++) {
			printf("%d ", C[i][j]);
		}
		putchar('\n');
	}
#endif

	// Check if C == I
	for (i = 0; i < mtrx_size; i++) {
		c = C[i];
		for (j = 0; j < mtrx_size; j++) {
			if (i == j) {
				if (c[i] != 1) {
					fprintf(stderr, "Error: "
						"C[%d][%d] = %d (!= 1)\n",
						i, i, c[i]);
					errno = EPERM;
					return -1;
				}
			}
			else if (c[j] != 0) {
				fprintf(stderr, "Error: C[%d][%d] = %d "
					"(!= 0)\n", i, j, c[j]);
				errno = EPERM;
				return -1;
			}
		}
	}

	return 0;
}

// Test matrix
int
Mod32TestMtrx(void)
{
	int		i, non_det_count, ret, repeat = 2000;
	uint32_t	*A[MAX_MOD_MTRX_SIZE], *invA[MAX_MOD_MTRX_SIZE];
	uint32_t	*C[MAX_MOD_MTRX_SIZE];

	// Initialize
	//Mod32Init();

	srand(time(NULL));
	for (i = 0; i < MAX_MOD_MTRX_SIZE; i++) {
		A[i] = malloc(sizeof(uint32_t) * MAX_MOD_MTRX_SIZE);
		invA[i] = malloc(sizeof(uint32_t) * MAX_MOD_MTRX_SIZE);
		C[i] = malloc(sizeof(uint32_t) * MAX_MOD_MTRX_SIZE);
	}

	// Test Mod32
	puts("Testing Mod32 matrix features:");
	non_det_count = 0;
	for (i = 0; i < repeat; i++) {
		//printf("%d\n", i);
		switch (Mod32Test(A, invA, C)) {
		case -1: // Failed
			fprintf(stderr, "Error: Test failed at iter %d\n", i);
			goto LOOP_EXIT;
		case 1: // Not invertible
			non_det_count++;
			break;
		case 0: // Passed
			break;
		default:
			break;
		}
	}

LOOP_EXIT:
	// 
	if (i == repeat) {
		puts("  Test passed");
		ret = 0;
	}
	else {
		puts("  Test failed");
		ret = -1;
	}

	// Print # of non-invertible matrices
	printf("  %d out of %d (%f%%) were non-invertible\n",
		non_det_count, repeat,
		(float)(non_det_count * 100) / (float)repeat);

	// Finalize
	for (i = 0; i < MAX_MOD_MTRX_SIZE; i++) {
		free(A[i]);
		free(invA[i]);
		free(C[i]);
	}
	
	return ret;
}
