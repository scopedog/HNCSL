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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <libgen.h>
#include <fts.h>
#include <ifaddrs.h> // Must be before <net/if.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#if defined(__FreeBSD__)
#include <sys/event.h>
#endif
#include <sys/time.h>
#include <sys/param.h>
#if defined(__linux__)
#include <sys/select.h>
#include <sys/sendfile.h>
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <event.h> // libevent
#include "net-common.h"
#include "server-common.h"
#if defined(_HNC_)
#include "enc_dec.h"
#endif
#include "net.h"
#include "message.h"
#include "memory.h"
#include "mt64.h"
#include "misc-common.h"
#include "log.h"
#include "util.h"

/**************************************************************************
	Definitions
**************************************************************************/

/**************************************************************************
	Structures
**************************************************************************/

/**************************************************************************
	Variables
**************************************************************************/

/**************************************************************************
	Pre-declaration of functions
**************************************************************************/

/**************************************************************************
	Functions
**************************************************************************/

#if defined(_HNC_)
// Set keys
size_t
SetKeys(HNCdatS *hnc_dat, void *data)
{
	int	h, i, j;
	uint8_t	*d = data;
	MOD_T	*key_mtrx_dec;

	// Copy key_beta
	memcpy(d, hnc_dat->key_beta, NUM_BETA_KEYS * SIMD_ENCRYPT_SIZE);
	d += NUM_BETA_KEYS * SIMD_ENCRYPT_SIZE;

	// Copy init_prev_c_prime
	memcpy(d, hnc_dat->init_prev_c_prime, HNC_RANK * 32);
	d += HNC_RANK * 32;

	// Copy key_mtrx_dec
	for (h = 0; h < NUM_MTRX_KEYS; h++) {
		for (i = 0; i < HNC_RANK; i++) {
/*
			memcpy(d, hnc_dat->key_mtrx_dec[h][i],
				sizeof(MOD_T) * HNC_RANK);
			d += sizeof(MOD_T) * HNC_RANK;
*/
			key_mtrx_dec = hnc_dat->key_mtrx_dec[h][i];
			for (j = 0; j < HNC_RANK; j++) {
				// Convert to net endian 
#if defined(_MOD16_)
				*((MOD_T *)d) = htons(*key_mtrx_dec);
#elif defined(_MOD32_)
				*((MOD_T *)d) = htonl(*key_mtrx_dec);
#endif
				d += sizeof(MOD_T);
				key_mtrx_dec++;
			}
		}
	}

	return d - (uint8_t *)data;
}
#endif // _HNC_

#if defined(_HNCSLD_)
// Exit thread
void
ExitThread(ThInf *tinf)
{
	char			*p;
	struct event_base	*ev_loop;

	// Close resources
	if ((ev_loop = tinf->evLoop) > 0) {
		event_base_free(ev_loop);
		tinf->evLoop = NULL;
	}
	DebugMsg("Client %s (tinf: %p): Connection closed\n",
		tinf->ipAddrS, tinf);

	// Delete .tmp.XXX path
	if ((p = strrchr(tinf->path, '/')) != NULL) { // Skip dir
		p++;
	}
	else {
		p = tinf->path;
	}
	if (strlen(p) == strlen(TMPF_TEMPLATE) && strncmp(p, ".tmp.", 5)
			== 0) { // .tmp.XXX path
		remove(tinf->path);
	}

	// Free space for this thread
	FreeSpaceThrInf(tinf);

	pthread_exit(NULL);
}
#endif // _HNCSLD_
