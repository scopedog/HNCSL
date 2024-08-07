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
#if 0
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#endif
#include <event.h> // libevent
#include "common.h"
#include "parm-common.h"
#include "server-common.h"
//#include "init.h"
#include "net.h"
#include "message.h"
#if defined(_HNC_)
#include "enc_dec.h"
#endif // _HNC_
#include "memory.h"
#include "misc-common.h"
#include "log.h"
#include "util.h"

/**************************************************************************
	Definitions
**************************************************************************/

#define NUM_LISTEN		16	// Size of SockListen

/**************************************************************************
	Structures
**************************************************************************/

#if 1
// SSL connection
typedef struct {
	int	sockListen; // Socket for listening
	int	sock; // Socket for transmission
	SSL_CTX	*ctx; // Context
} SSLinf;
#endif

/**************************************************************************
	Variables
**************************************************************************/

int	SockListen[NUM_LISTEN], NumSockListen;
SSLinf	SSLcon[NUM_LISTEN];

/**************************************************************************
	Pre-declaration
**************************************************************************/
/**************************************************************************
	Functions
**************************************************************************/

#if 0
// In future, we'll share HNC keys thgrough SSL
// Initialize SSL
static int
InitSSL(void)
{
	SSL_CTX	*ctx; // Context

	// Set CERT paths
	InitCert();

	// Initialize SSL
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_ssl_algorithms();

	// Create context
	if ((SSLcon[0].ctx = ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
		LogSSLError("SSL_CTX_new", NULL, 0);
		exit(EXIT_FAILURE);
	}

	// Set cert
	if (SSL_CTX_use_certificate_file(ctx, CertPEM, SSL_FILETYPE_PEM)
			<= 0) {
		LogSSLError("SSL_CTX_use_certificate_file", NULL, 0);
                exit(EXIT_FAILURE);
        }

	// Set private key
        if (SSL_CTX_use_PrivateKey_file(ctx, PrivKeyPEM, SSL_FILETYPE_PEM)
			<= 0) {
		LogSSLError("SSL_CTX_use_PrivateKey_file", NULL, 0);
		puts(PrivKeyPEM);
                exit(EXIT_FAILURE);
        }


	return 0;
}
#endif

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

// Initialize network
void
InitNet(void)
{
	int		sock, err = 0, opt_val = 1;
	struct addrinfo	hints, *addr = NULL;
	struct addrinfo	*ad;

#if 0
	// Init SSL
	if (InitSSL() == -1) {
		exit(EXIT_FAILURE);
	}
#endif

	// Prepare for listening
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((err = getaddrinfo(NULL, Config.port_s, &hints, &addr))) { // Err
		ShowGetaddrinfoErr(__func__, err, "localhost for bind");
		Log("Error: %s: Couldn't obtain IP address info of local host. "
		    "Quit..", __func__);
		exit(EXIT_FAILURE);
	}

#if 1
	MyBool	ipv6_exists = False;
	struct addrinfo	*ad_v4 = NULL;

	// Check if there is v6 address
	for (ad = addr; ad != NULL; ad = ad->ai_next) {
		switch (ad->ai_family) {
		case AF_INET:
			ad_v4 = ad;
			break;

		case AF_INET6:
			ipv6_exists = True;
			goto PREP_LISTEN;

		default:
			break;
		}
	}

PREP_LISTEN:
	// Check if IPv4 only
	if (!ipv6_exists) {
		if (ad_v4 == NULL) { // No v4 address found
			Log("Error: Neither IPv4 nor IPv6 address assigned to "
			    "this host. Quit..");
				exit(EXIT_FAILURE);
		}
		else {
			ad = ad_v4;
		}
	}

	// Open socket for listening to connection from clients
	if ((sock = socket(ad->ai_family, ad->ai_socktype, ad->ai_protocol))
			< 0) {
		Log("Error: %s: socket: %s. Quit..", __func__, strerror(errno));
		exit(EXIT_FAILURE);
       	}
	SockListen[0] = sock;

	// Set SO_REUSEADDR
	opt_val = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			&opt_val, sizeof(opt_val)) < 0) {
		Log("Error: %s: setsockopt(SO_REUSEADDR): %s",
			__func__, strerror(errno));
		exit(EXIT_FAILURE);
       	}

	// Turn off IPV6_V6ONLY
	opt_val = 0;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
			&opt_val, sizeof(opt_val)) < 0) {
		Log("Error: %s: setsockopt(IPV6_V6ONLY): %s",
			__func__, strerror(errno));
		exit(EXIT_FAILURE);
       	}

	// Bind
	if (ipv6_exists) { // IPv6
#if defined(__FreeBSD__) || defined(__APPLE__)
		struct sockaddr_in6 sv_addr;

		// Initialize
		memset(&sv_addr, 0, sizeof(sv_addr));
		sv_addr.sin6_family = AF_INET6;
		sv_addr.sin6_port = htons(Config.port);
		sv_addr.sin6_addr = in6addr_any;

		// Bind
		if (bind(sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr))
				< 0) {
			Log("Error: %s: bind IPv6 address: %s. Quit..",
	    			__func__, strerror(errno));
			exit(EXIT_FAILURE);
		}

#elif defined(__linux__)
		// Free previous addr inf first
		if (addr != NULL) {
			freeaddrinfo(addr);
		}

		// Get addr info
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
		if ((err = getaddrinfo("::0", Config.port_s, &hints, &addr))) {
			// Err
			ShowGetaddrinfoErr(__func__, err, "IPv6 for bind");
			Log("Error: %s: Couldn't obtain IP address info. "
				"Quit..", __func__);
			exit(EXIT_FAILURE);
		}

		// Bind
		if (bind(sock, addr->ai_addr, addr->ai_addrlen) < 0) {
			Log("Error: %s: bind IPv6 address: %s. Quit..",
	    			__func__, strerror(errno));
			exit(EXIT_FAILURE);
		}
#endif
	}
	// IPv4
	else if (bind(sock, ad->ai_addr, ad->ai_addrlen) < 0) {
		Log("Error: %s: bind: %s. Quit..",
	    		__func__, strerror(errno));
		exit(EXIT_FAILURE);
       	}

	// Listen
	if (listen(sock, MAX_CONNECTIONS) < 0) {
		Log("Error: %s: listen: %s. Quit..", __func__, strerror(errno));
		exit(EXIT_FAILURE);
        }
	NumSockListen = 1;

#else
	int	i;

	// Listen 
	for (ad = addr, i = 0; ad != NULL && i < NUM_LISTEN;
	     ad = ad->ai_next, i++) {
		// Open socket for listening to connection from clients
		if ((sock = socket(ad->ai_family, ad->ai_socktype,
					ad->ai_protocol)) < 0) {
			Log("Error: socket SocketListen[%d]: %s. Quit..",
		    		i, strerror(errno));
			exit(EXIT_FAILURE);
        	}
		SockListen[i] = sock;

		// Set SO_REUSEADDR
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				&on, sizeof(on)) < 0) {
			Log("Error: %s: setsockopt(SO_REUSEADDR): %s", __func__,
				strerror(errno));
			exit(EXIT_FAILURE);
        	}

		// Bind
		if (bind(sock, ad->ai_addr, ad->ai_addrlen) < 0) {
			Log("Error: bind SocketListen[%d]: %s. Quit..",
		    		i, strerror(errno));
			exit(EXIT_FAILURE);
        	}

		// Listen
		if (listen(sock, MAX_CONNECTIONS) < 0) {
			Log("Error: listen SocketListen[%d]: %s. Quit..",
		    		i, strerror(errno));
			exit(EXIT_FAILURE);
        	}
	}
	NumSockListen = i;
#endif

	// Finalize
	if (addr != NULL) {
		freeaddrinfo(addr);
	}
}

// Initialize for session
static int
InitSession(ThInf *tinf)
{
	//tinf->mode = 0;
	tinf->basePath[0] = '\0';
	tinf->path[0] = '\0';
	tinf->err = 0;

	// Allocate and initialize HNCdat
	if (tinf->hncDat == NULL) {
		if ((tinf->hncDat = AllocHNCdat()) == NULL) {
			Log("Error: %s: AllocHNCdat: %s",
				__func__, strerror(errno));
			return -1;
		}
	}
	InitHNCdat(tinf->hncDat);

	return 0;
}

// Receive message from client
static void
ProcClientMsg(ThInf *tinf)
{
	int		h, i, j, ret, err = 0;
	int		sock = tinf->sock;
	size_t		size;
	uint8_t		*enc_dat = tinf->rcvDat;
	uint8_t		*org_dat = NULL;
	uint8_t		*dec_dat = tinf->sndDat; // Decrypted yata
	MOD_T		**key_mtrx_dec, *_key_mtrx_dec, tmp[HNC_RANK];
	uint64_t	reply_msg;
	HNCdatS		*hnc_dat;

	// Initialize for this session
	InitSession(tinf);
	hnc_dat = tinf->hncDat;

	// Receive key_beta
	if ((size = read(sock, hnc_dat->key_beta,
			NUM_BETA_KEYS * SIMD_ENCRYPT_SIZE)) == -1) {
		Log("Error: %s: read key_beta: %s",
			__func__, strerror(errno));
		err = errno;
		goto END;
	}
	else if (size == 0) { // This happens when disconnected
		//Log("Error: Disconnected", __func__);
		err = errno = ECONNRESET;
		goto END;
	}

	// Receive init_prev_c_prime
	if ((size = read(sock, hnc_dat->init_prev_c_prime, HNC_RANK * 32))
			== -1) {
		Log("Error: %s: read init_prev_c_prime: %s",
			__func__, strerror(errno));
		err = errno;
		goto END;
	}
	else if (size == 0) { // This happens when disconnected
		//Log("Error: Disconnected", __func__);
		err = errno = ECONNRESET;
		goto END;
	}

	// Receive key_mtrx_dec 
	for (h = 0; h < NUM_MTRX_KEYS; h++) {
		key_mtrx_dec = hnc_dat->key_mtrx_dec[h];
		for (i = 0; i < HNC_RANK; i++) {
			// Receive
			if ((size = read(sock, tmp, sizeof(MOD_T) * HNC_RANK))
					== -1) {
				Log("Error: %s: read key_mtrx_dec: %s",
					__func__, strerror(errno));
				err = errno;
				goto END;
			}

			// Convert to host endian
			_key_mtrx_dec = key_mtrx_dec[i];
			for (j = 0; j < HNC_RANK; j++) {
#if defined(_MOD16_)
				*_key_mtrx_dec = ntohs(tmp[j]);
#elif defined(_MOD32_)
				*_key_mtrx_dec = ntohl(tmp[j]);
#endif
				_key_mtrx_dec++;
			}

/* Debug
			printf("%04x, %04x, %04x, %04x\n",
				key_mtrx_dec[i][0], key_mtrx_dec[i][1],
				key_mtrx_dec[i][2], key_mtrx_dec[i][3]);
*/
		}
	}

	// Allocate org_dat
	if ((org_dat = aligned_alloc(32, SEND_DAT_SIZE)) == NULL) {
		Log("Error: %s: aligned_alloc org_dat: %s",
			__func__, strerror(errno));
		err = errno;
		goto END;
	}

	// Receive original data
	if ((size = ReadAll(sock, org_dat, SEND_DAT_SIZE)) == -1) {
		Log("Error: %s: read org_dat: %s", __func__, strerror(errno));
		err = errno;
		goto END;
	}

	// Reply
	if ((ret = write(sock, &reply_msg, sizeof(uint64_t))) <= 0) {
		Log("Error: %s: write: %s", __func__, strerror(errno));
		err = errno;
		goto END;
	}

	// Initialize hnc_dat for this session
	//SetSampleHNCkey(hnc_dat);
	SetHNCdatCod(hnc_dat);

	// Receive encoded data
	for (i = 0; i < SEND_REPEAT; i++) {
		// Receive encoded data from client
		if ((size = ReadAll(sock, enc_dat, SEND_DAT_SIZE)) == -1) {
			Log("Error: %s: read enc_dat: %s",
				__func__, strerror(errno));
			err = errno;
			goto END;
		}
		else if (size == 0) {
			Log("Info: %s: Connection closed", __func__);
			err = 1;
			goto END;
		}

		// Decrypt in this thread
		HNCDecrypt(hnc_dat, enc_dat, dec_dat, size);

#if 0 // Debug - Compare original data and decoded data
		// Debug - Compare org_dat and dec_dat
		if (memcmp(org_dat, dec_dat, size)) { // Did not match
			Log("Error: %s: Decrypt data and original data are "
			    "different (i = %d, size = %ld)",
				__func__, i, size);
			err = EPERM;
/*
ShowBytes(enc_dat + size - 160, 64);
ShowBytes(dec_dat + size - 160, 64);
*/

			goto END;
		}
		else { // Matched
			//puts("Data match");
		}
#endif
	}

	// Reply to client
	if ((ret = write(sock, enc_dat, sizeof(uint64_t))) <= 0) {
		Log("Error: %s: write: %s", __func__, strerror(errno));
		err = errno;
		goto END;
	}

/*
	DebugMsg("Client %s (tinf: %p): %d byte message received\n",
		tinf->ipAddrS, tinf, ret);
*/

END:	// Finalize
	if (org_dat != NULL) {
		free(org_dat);
	}

	if (err) {
		ExitThread(tinf);
	}
}

// Receive message from client
static void
OnClientMsg(evutil_socket_t sock, short e, void *data)
{
	ThInf		*tinf = (ThInf *)data;
	int		ret, err;
	socklen_t	len;

	// Check error
	err = errno = 0;
	len = sizeof(err);
	ret = getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
	if (err) {
		errno = err;
	}
	if (ret < 0 || errno) {
		if (errno != ECONNRESET) {
			Log("Error: %s: Client %s: getsockopt: %s",
				__func__, tinf->ipAddrS, strerror(errno));
		}
		ExitThread(tinf);
	}

	// Receive message from client
	ProcClientMsg(tinf);
}

// Process client 
static void *
ProcClientThread(void *data)
{
	int			ret, sock;
	//struct timespec	ts = {120, 0}; // Timeout in 120 sec
	ThInf			*tinf = (ThInf *)data;
	struct event_base	*ev_base;
	struct event		ev;

	// Initialize
	sock = tinf->sock;

	// Detach this thread
	if ((ret = pthread_detach(pthread_self()))) {
		Log("Error: %s: pthread_detach: %s",
			__func__, strerror(ret));
		pthread_exit(NULL);
	}

	// Connection accepted
	DebugMsg("Client %s (tinf: %p): Connection accepted\n",
		tinf->ipAddrS, tinf);

	// Initialize loop event
	if ((ev_base = event_base_new()) == NULL) {
		Log("Error: %s: event_base_new: %s",
			__func__, strerror(errno));
		ExitThread(tinf);
	}
	tinf->evLoop = ev_base;
	event_set(&ev, sock, EV_READ | EV_PERSIST, OnClientMsg, tinf);
	event_base_set(ev_base, &ev);
	if (event_add(&ev, NULL)) {
		Log("Error: %s: event_add: %s", __func__, strerror(errno)); 
		ExitThread(tinf);
	}

	// Receive message from client
	event_base_dispatch(ev_base);

	return NULL;
}

// Process client
static void
ProcessClient(int sock, struct sockaddr_storage *addr, HInfB *hInfB)
{
	int		ret, errc;
	pthread_t	id;
	ThInf		*tinf;

#if 1	// Use memory pool
	// Find space in memory pool
	if ((tinf = FindSpaceThrInf()) == NULL) {
		Log("Error: %s: FindSpaceThrInf: Out of memory", __func__);
		return;
	}
#else
	// Allocate tinf
	if ((tinf = (ThInf *)aligned_alloc(32, sizeof(ThInf))) == NULL) {
		Log("Error: %s: aligned_alloc: %s", __func__, strerror(errno));
		return;
	}
#endif

	// Initialize tinf
	//tinf->mode = 0;
	tinf->sock = sock;
	tinf->sockMutexInit = False;
	//tinf->ssl = SSL_new(SSLcon[0].ctx);

#if 0	// In future, we'll share HNC keys thgrough SSL
	// Initialize SSL
	SSL_set_fd(tinf->ssl, sock);
	if ((ret = SSL_accept(tinf->ssl)) <= 0) {
		LogSSLError("SSL_accept", tinf->ssl, ret);
		return;
	}
#endif

	// Initialize client address
	memcpy(&tinf->addr, addr, sizeof(struct sockaddr_storage));
	if ((errc = getnameinfo((struct sockaddr *)addr,
			sizeof(struct sockaddr_storage), tinf->ipAddrS, 64,
			NULL, 0, NI_NUMERICHOST))) {
		Log("Warning: getnameinfo: %s", gai_strerror(errc));
	}

	// Initialize misc
	tinf->basePath[0] = '\0';
	tinf->path[0] = '\0';
	tinf->err = 0;
	tinf->evLoop = NULL;
	if ((tinf->rcvDat = FindSpaceRcvDat()) == NULL) {
		Log("Error: %s: FindSpaceRcvDat: %s",
			__func__, strerror(errno));
		return;
	}
	if ((tinf->sndDat = FindSpaceRcvDat()) == NULL) {
		Log("Error: %s: FindSpaceRcvDat: %s",
			__func__, strerror(errno));
		return;
	}

	// Launch new thread
	if ((ret = pthread_create(&id, NULL, ProcClientThread, tinf))) {
		Log("Error: %s: pthread_create: %s", __func__, strerror(ret));
	}
}

// On accepting connection
static void
OnAccept(evutil_socket_t sock, short e, void *data)
{
	int			accept_sock, sockopt;
	struct sockaddr_storage	client_addr;
	socklen_t		client_len = sizeof(client_addr);
	HInfB			*hInfB = NULL;

	// Accept
	if ((accept_sock = accept(sock,
			(struct sockaddr *)&client_addr, &client_len)) < 0) {
		Log("Error: %s: accept: %s", __func__, strerror(errno));
		return;
	}

	// Change snd/recv buf size -- Slow?
	//SetSndRcvBufSiz(accept_sock, SNDRCV_BUFSIZ);

#if defined(__FreeBSD__)
	// Set SO_NOSIGPIPE option
	sockopt = 1;
	if (setsockopt(accept_sock, SOL_SOCKET, SO_NOSIGPIPE, &sockopt,
			sizeof(sockopt)) == -1) {
		Log("Warning: %s: setsockopt SO_NOSIGPIPE: %s",
			__func__, strerror(errno));
	}
#endif

#if 1
	// Set some options
	if (setsockopt(accept_sock, IPPROTO_TCP, TCP_NODELAY, &sockopt,
			sizeof(int)) < 0) {
		Log("Warning: %s: setsockopt TCP_NODELAY: %s",
			strerror(errno));
	}

	// SO_RCVLOWAT
	sockopt = 8;
	if (setsockopt(accept_sock, SOL_SOCKET, SO_RCVLOWAT, &sockopt,
			sizeof(int)) < 0) {
		Log("Warning: %s: setsockopt SO_RCVLOWAT: %s",
			__func__, strerror(errno));
	}
#endif

#ifdef USE_IPTOS_OPTIONS
	sockopt = IPTOS_LOWDELAY;
	if (setsockopt(accept_sock, IPPROTO_IP, IP_TOS, &sockopt,
			sizeof(int)) < 0) {
		Log("Warning: %s: setsockopt IPTOS_LOWDELAY: %s",
			__func__, strerror(errno));
	}

	sockopt = IPTOS_THROUGHPUT;
	setsockopt(accept_sock, IPPROTO_IP, IP_TOS, &sockopt,
		sizeof(int));
#endif
		
	// Process client
	ProcessClient(accept_sock, &client_addr, hInfB);
}

// Net loop
void
LoopNet()
{
	int			i, ev_idx;
	struct event_base	*ev_base;
	struct event		*ev = NULL, *_ev;

	// Initialize loop event
	if ((ev_base = event_base_new()) == NULL) {
		Log("Error: %s: event_base_new: %s", __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Allocate ev
	if ((ev = (struct event *)malloc(sizeof(struct event) *
				NumSockListen)) == NULL) {
		Log("Error: %s: malloc ev: %s", __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Add non-SSL sockets
	ev_idx = 0;
	for (i = 0; i < NumSockListen; i++) {
		// Add SockListen to receive 'accept' event
		_ev = &ev[ev_idx];
		event_assign(_ev, ev_base, SockListen[i],
			EV_READ | EV_PERSIST, OnAccept, (void *)0);
		if (event_add(_ev, NULL)) {
			Log("Error: %s: event_add: %s",
				__func__, strerror(errno));
			exit(EXIT_FAILURE);
		}
		ev_idx++;
	}

	// Loop for accepting connection
	event_base_dispatch(ev_base);

	// Exit loop
	event_base_free(ev_base);
	if (ev != NULL) {
		free(ev);
	}
}

// Send error to client
int
SendError(ThInf *tinf, const char *msg, int err)
{
	char	buf[BUFSIZ], *p;
	int	ret, sock = tinf->sock;
	size_t	len;

	/* Create message like:
		<error>Error message: xxxx</error>
	*/
	p = stpncpy(buf, "<?xml version = \"1.0\"?>\n<error>", sizeof(buf));
	len = p - buf;
	p = stpncpy(p, msg, sizeof(buf) - len);
	len = p - buf;
	p = stpncpy(p, ": ", sizeof(buf) - len); 
	len = p - buf;
	p = stpncpy(p, strerror(errno), sizeof(buf) - len); 
	len = p - buf;
	p = stpncpy(p, "</error>", sizeof(buf) - len);
	len = p - buf;

	// Send
	if ((ret = write(sock, buf, len)) <= 0) {
		Log("Error: %s: write: %s", __func__, strerror(errno));
		return -1;
	}

	tinf->err = err;

	return 0;
}
