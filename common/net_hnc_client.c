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
#include <sys/types.h>
#include <sys/stat.h>
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
#include "common.h"
#include "parm-common.h"
#include "net.h"
#include "memory.h"
#include "misc-common.h"
#include "log.h"
#include "util.h"

// Initialize my hostname and IP addresses
int
InitMyHostnameIP(void)
{
	struct utsname	hname;

	// Get my hostname
	if (uname(&hname) < 0) {
		Log("Error: %s: uname: %s", __func__, strerror(errno));
		return -1;
	}
	strncpy(MyHostname, hname.nodename, sizeof(MyHostname));

	// Get my addrinfo
	if (GetMyAddrInfo(&MyAddr) == -1) {
		Log("Error: %s: %s: Failed to obtain my IP addresses",
			__func__, strerror(errno));
		return -1;
	}

	// Set localhost address
	LocalHostAddr = inet_addr("127.0.0.1");

	return 0;
}

// Connect to server
int
ConnectToServer(const char *server_name)
{
	int	sock = -1, err = 0;
	HInf	hInf;

	// Connect to server
	InitHInf(&hInf, server_name, NULL);
	if (ConnectToHost(&hInf, Config.port, 7000) == -1) {
		err = errno;
		Log("Error: %s: %s", __func__, strerror(errno));
		goto END;
	}
	sock = hInf.sock;

	// Set TCP_NODELAY 
	//SockSetTcpNoDelay(sock, true);

	// Change send/recv buf size -- Slow?
	//SetSndRcvBufSiz(sock, SNDRCV_BUFSIZ);

END:
	return err ? -1 : sock;
}
