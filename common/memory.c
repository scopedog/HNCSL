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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/file.h>
#if defined(_OPENSSL_)
#include <openssl/ssl.h>
#endif
#if defined(_HNC_)
#include "end_dec.h"
#endif
#include "memory.h"
#include "server-common.h"
#include "net.h"
#include "mt64.h"
#include "log.h"
#include "util.h"

/************************************************************
	Functions
************************************************************/

// Initialize memory spaces
void
InitMem(void)
{
	int	ret;
	size_t	size;

	// Allocate memory for ThrInf
	size = sizeof(ThInf) * MAX_CONNECTIONS;
	if ((ThrInf = (ThInf *)aligned_alloc(32, size)) == NULL) {
		Log("Error: %s: aligned_alloc ThrInf: %s",
			__func__, strerror(errno));
		exit(1);
	}
	memset(ThrInf, 0, size);
	//DebugMsg("ThrInf test: %u\n", (ThrInf + 1) - ThrInf);

	// Initialize ThrInf memory usage map
	TIMap = BitSetCreate(MAX_CONNECTIONS);
	if ((ret = pthread_mutex_init(&TIMutex, NULL))) {
		Log("Error: %s: pthread_mutex_init TIMutex: %s",
			__func__, strerror(ret));
		exit(1);
	}

#if 0
	// Allocate memory for RcvDat
	size = sizeof(uint8_t) * RECV_DAT_SIZE * NUM_OF_RCVDAT;
	if ((RcvDat = (uint8_t *)aligned_alloc(32, size)) == NULL) {
		Log("Error: %s: aligned_alloc RcvDat: %s",
			__func__, strerror(errno));
		exit(1);
	}

	// Initialize RcvDat memory usage map
	RDMap = BitSetCreate(NUM_OF_RCVDAT);
	if ((ret = pthread_mutex_init(&RDMutex, NULL))) {
		Log("Error: %s: pthread_mutex_init RDMutex: %s",
			__func__, strerror(ret));
		exit(1);
	}
#endif
}

// Find open space in ThrInf
ThInf *
FindSpaceThrInf(void)
{
	unsigned int	nn, n = (unsigned int)(genrand64_int64() & UINT_MAX) %
					MAX_CONNECTIONS;

	// Check TIMap
	nn = n;
	pthread_mutex_lock(&TIMutex);
	while (BitSetIsSet(TIMap, n)) {
		n++;
		if (n >= MAX_CONNECTIONS) {
			n = 0;
		}
		if (n == nn) { // Memory full
			Log("Error: %s: Memory full", __func__);
			errno = ENOMEM;
			pthread_mutex_unlock(&TIMutex);
			return NULL;
		}
	}

	// Mark n as used
	BitSetSet(TIMap, n, 1);
/*
	if (Debug) {
		fputs("Alloc TIMap: ", stdout);
		BitSetShowAll(TIMap);
	}
*/
	pthread_mutex_unlock(&TIMutex);

	return ThrInf + n;
}

// Free space in ThrInf -- If you change this, also change FreeAllSpacesThrInf()
void
FreeSpaceThrInf(ThInf *tinf)
{
	int	sock;
	StrList	*strList = &tinf->strList;

	// Free rcvDat
	if (tinf->rcvDat != NULL) {
		FreeSpaceRcvDat(tinf->rcvDat);
		tinf->rcvDat = NULL;
	}

	// Free sndDat
	if (tinf->sndDat != NULL) {
		FreeSpaceRcvDat(tinf->sndDat);
		tinf->sndDat = NULL;
	}

	// Lock sockMutex
	if (tinf->sockMutexInit) {
		pthread_mutex_lock(&tinf->sockMutex);
	}

	// Disconnect with client -- THIS SHOULD BE DONE HERE!!!!!
	if ((sock = tinf->sock) > 0) {
//fprintf(stderr, "Closing %s (%d)\n", tinf->clName, sock);
#if defined(_OPENSSL_)
		SSL_shutdown(tinf->ssl);
		SSL_free(tinf->ssl);
		tinf->ssl = NULL;
#endif
		close(sock);
		tinf->sock = 0;
	}

	// Unlock sockMutex and destroy
	if (tinf->sockMutexInit) {
		pthread_mutex_unlock(&tinf->sockMutex);
		pthread_mutex_destroy(&tinf->sockMutex);
		tinf->sockMutexInit = False;
	}

	// Free strList
	if (strList->list != NULL) {
		StrListFree(strList);
		strList->list = NULL;
		strList->size = 0;
		strList->len = 0;
	}

	// Lock
	pthread_mutex_lock(&TIMutex);

	// Just mark open in TIMap
	BitSetSet(TIMap, tinf - ThrInf, 0);
/*
	if (Debug) {
		fputs("Free  TIMap: ", stdout);
		BitSetShowAll(TIMap);
	}
*/
	pthread_mutex_unlock(&TIMutex);
}

#if defined(_HNCSLD_)
// Find open space in RcvDat
uint8_t *
FindSpaceRcvDat(void)
{
#if 1
	return aligned_alloc(32, SEND_DAT_SIZE);
#else
	unsigned int	nn, n = (unsigned int)(genrand64_int64() & UINT_MAX) %
					NUM_OF_RCVDAT;

	// Check RDMap
	nn = n;
	pthread_mutex_lock(&RDMutex);
	while (BitSetIsSet(RDMap, n)) {
		n++;
		if (n >= NUM_OF_RCVDAT) {
			n = 0;
		}
		if (n == nn) { // Memory full
			Log("Error: %s: Memory full", __func__);
			errno = ENOMEM;
			pthread_mutex_unlock(&RDMutex);
			return NULL;
		}
	}

	// Mark n as used
	BitSetSet(RDMap, n, 1);
/*
	if (Debug) {
		fputs("Alloc RDMap: ", stdout);
		BitSetShowAll(RDMap);
	}
*/
	pthread_mutex_unlock(&RDMutex);

	return RcvDat + (n * SEND_DAT_SIZE);
#endif
}

// Free space in RcvDat
void
FreeSpaceRcvDat(uint8_t *rcvd)
{
#if 1
	free(rcvd);
#else
	// Just mark open in RDMap
	pthread_mutex_lock(&RDMutex);
	BitSetSet(RDMap, (rcvd - RcvDat) / SEND_DAT_SIZE, 0);
/*
	if (Debug) {
		fputs("Free  RDMap: ", stdout);
		BitSetShowAll(RDMap);
	}
*/
	pthread_mutex_unlock(&RDMutex);
#endif
}
#endif
