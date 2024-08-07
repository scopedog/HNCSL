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
#include <ctype.h>
#include <netdb.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/time.h>
#if defined(__linux__)
#include <sys/sendfile.h>
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "common.h"
#include "parm-common.h"
//#include "net.h"
#include "misc-common.h"
#include "log.h"
#include "util.h"

/**************************************************************************
	Definitions
**************************************************************************/

// USE_IPTOS_OPTIONS is not supported in IPv6
//#define USE_IPTOS_OPTIONS	// Use IPTOS options

/**************************************************************************
	Structures
**************************************************************************/

/**************************************************************************
	Variables
**************************************************************************/

/**************************************************************************
	Declaration of static functions
**************************************************************************/

/**************************************************************************
	Functions
**************************************************************************/

// Check sock status
int
CheckSockStat(int sock)
{
	char		buf[64];
	int		ret;
	fd_set		fdset_r, fdset_w;
	struct timeval	tv = {4, 0};

	sleep(1);

	FD_ZERO(&fdset_r);
	FD_ZERO(&fdset_w);
	FD_SET(sock, &fdset_r);
	FD_SET(sock, &fdset_w);
	Log("%s: Checking sock %d", __func__, sock);

	// Select
	ret = select(sock + 1, &fdset_r, &fdset_w, NULL, &tv);
	switch (ret) {
	case -1:
		Log("Error: %s: select: %s", __func__, strerror(errno));
		return -1;
	case 0:
		Log("Error: %s: select: Time out", __func__);
		return -1;
	default:
		break;
	}
	errno = 0;

	// Try to recv
	if (FD_ISSET(sock, &fdset_r)) {
		if (recv(sock, buf, sizeof(buf), 0) == -1) {
			Log("Error: %s: recv: %s", __func__, strerror(errno));
		}
		else {
			Log("%s: recv: OK", __func__);
		}
	}

	// Try to send
	if (FD_ISSET(sock, &fdset_w)) {
		if (send(sock, buf, sizeof(buf), MSG_NOSIGNAL) == -1) {
			Log("Error: %s: send: %s", __func__, strerror(errno));
		}
		else {
			Log("%s: send: OK", __func__);
		}
	}

	return errno ? -1 : 0;
}

// Initialize hInf
void
InitHInf(HInf *hInf, const char *name, HInfB *hInfB)
{
	hInf->name = name;
	hInf->sock = 0;
	hInf->status = HOST_DEAD;
	hInf->err = 0;
	hInf->hInfB = hInfB;
}

// Close server
void
CloseHost(HInf *h_inf)
{
	int	sock;

	h_inf->status = HOST_DEAD;
	sock = h_inf->sock;
	if (sock > 0) {
		close(sock);
		h_inf->sock = -1;
	}
}

// Connection to host returned. Check connection, send message, etc
static int
ConnectResponded(HInf *hInf, int optFlg)
{
	const char	*name = hInf->name;
	int		err = 0, eerr, sock = hInf->sock, sockop;
	unsigned long	ioctl_mode = 0;
	socklen_t	len;

	// Initialize
	hInf->err = 0;

	// Set sock blocking
	ioctl(sock, FIONBIO, &ioctl_mode);

	// Check error
	eerr = 0;
	len = sizeof(eerr);
	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &eerr, &len) < 0) {
		Log("Error: %s: getsockopt: %s", __func__, strerror(errno));
		err = errno;
		goto END;
	}
	if (eerr) { // Error
		Log("Warning: %s: Host %s: %s",
			__func__, name, strerror(eerr));
		err = errno = eerr;
		goto END;
	}

	//DebugMsg("Connected: sock %d\n", sock);

#if defined(__FreeBSD__)
	// Connected
	// Set SO_NOSIGPIPE option
	sockop = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &sockop,
			sizeof(sockop)) == -1) {
		Log("Warning: %s: setsockopt SO_NOSIGPIPE: %s",
			__func__, strerror(errno));
	}
#endif

	// Connected - set other socket options
	if (optFlg) {
		// TCP_NODELAY
		sockop = 1;
		if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &sockop,
				sizeof(int)) < 0) {
			Log("Warning: %s: setsockopt TCP_NODELAY: %s",
				__func__, strerror(errno));
		}

#ifdef USE_IPTOS_OPTIONS
		sockop = IPTOS_LOWDELAY;
		setsockopt(sock, IPPROTO_IP, IP_TOS, &sockop, sizeof(int));
#endif
	}
	hInf->status = HOST_ALIVE;
	DebugMsg("%s: Connected (sock %d)\n", name, sock);

END:
	// Finalize
	if (err) {
		hInf->status = HOST_DEAD;
		hInf->err = err;
		if (sock > 0) {
			CloseHost(hInf);
		}
		errno = err;
		return -1;
	}
	else {
		return 0;
	}
}


// Simply connect to host
int
ConnectToHost(HInf *hInf, u_short port, int timeOutMs)
{
	char		portS[16];
	const char	*name;
	int		sock = 0, ret, maxfd, err = 0;
	unsigned long	ioctl_mode = 1;
	fd_set		rset, wset;
	struct addrinfo	hints, *addr = NULL;
	div_t		d = div(timeOutMs, 1000);
	struct timeval	tv = {d.quot, d.rem * 1000}; // Timeout

	// Initialize
	snprintf(portS, sizeof(portS), "%u", port);
	if (timeOutMs >= 0) {
                d = div(timeOutMs, 1000);
                tv.tv_sec = d.quot;
                tv.tv_usec = d.rem * 1000;
        }
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	// Check name
	if ((name = hInf->name) == NULL) {
		return -1;
	}

	if (HsInfMeB != NULL) {
		if (strcmp(name, HsInfMeB->name) == 0) {
			// If it's me, then replace name with localhost
			name = "localhost";
		}
	}

	// Get IP addresses
	if ((err = getaddrinfo(name, portS, &hints, &addr))) {
		ShowGetaddrinfoErr(__func__, err, name);
		err = errno;
		goto END;
	}

	// Create socket
	if ((hInf->sock = sock =
		socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol))
			== -1) {
		Log("Error: %s: socket: %s", __func__, strerror(errno));
		err = errno;
		goto END;
	}

	// Set socket non-blocking
	ioctl(sock, FIONBIO, &ioctl_mode);

	// Connect
	ret = connect(sock, addr->ai_addr, addr->ai_addrlen);
	freeaddrinfo(addr);
	addr = NULL;
	if (ret < 0 && errno != EINPROGRESS) {
		Log("Error: %s: connect %s: %s",
	    		__func__, name, strerror(errno));
		err = errno;
		goto END;
	}
	else if (ret == 0) { // Immediately connected
		// Send msg, etc
		if (ConnectResponded(hInf, 0) == -1) {
			err = errno;
		}
		goto END;
	}
	else { // Connecting
		// Initialize for receving event
		maxfd = sock + 1;
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		FD_SET(sock, &rset);
		FD_SET(sock, &wset);
		hInf->status = HOST_CONNECTING;
	}

	// Wait for connection being done
	if ((ret = select(maxfd, &rset, &wset, NULL,
			(timeOutMs >= 0) ? &tv : NULL)) == -1) {
		Log("Error: %s: select: %s", __func__, strerror(errno));
		err = errno;
		goto END;
	}
	else if (ret == 0) { // Timeout
		Log("Warning: %s: Host %s: Connection failed (timeout)",
			__func__, name);
		err = ETIMEDOUT;
		goto END;
	}
	else { // Connected
		// Send msg, etc
		if (ConnectResponded(hInf, 0) == -1) {
			err = errno;
		}
	}

END:
	// Finalize
	ioctl_mode = 0;
	ioctl(sock, FIONBIO, &ioctl_mode);
	if (addr != NULL) {
		freeaddrinfo(addr);
	}

	if (err) {
		if (sock > 0) {
			CloseHost(hInf);
		}
		return -1;
	}
	else {
		return 0;
	}
}
