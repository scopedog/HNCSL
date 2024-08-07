/************************************************************************
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
************************************************************************/

#ifndef _HNCSL_COMMON_H_
#define _HNCSL_COMMON_H_

#include <stdint.h>
#include <limits.h>
#include <time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>

#include "custom.h" // Include this here 
#if defined(_amd64_)
#include <smmintrin.h>
#include <immintrin.h>
#elif defined(_arm64_)
#include <arm_neon.h>
#endif

#define _LIBEVENT_
#if !defined(MAXLOGNAME)
#define MAXLOGNAME	32
#endif

/*********************************************************************
	Definitions
*********************************************************************/

// HNC definitions
#define HNC_RANK_R		(HNC_RANK + HNC_RDUNDCY)

// Mod definitions
#if defined(_MOD8_)
typedef uint8_t		MOD_T; // MOD8
#define MOD_T_MAX	((1 << 8) - 1) // uint8_t max
#elif defined(_MOD16_)
typedef uint16_t	MOD_T; // MOD16
#define MOD_T_MAX	((1L << 16) - 1) // uint16_t max
#elif defined(_MOD32_)
typedef uint32_t	MOD_T; // MOD32
#define MOD_T_MAX	((1LL << 32) - 1) // uint32_t max
#elif defined(_OPENSSL_) || defined(_BORINGSSL_) || defined(_MSQUIC_) || defined(_NO_CRYPT_) // Dummy
typedef uint8_t		MOD_T;
#else
#error "No _MOD?_ specifed"
#endif

// Vector definitions
#if defined(__AVX2__)
typedef __m256i		VEC_T; // 256bit = 32byte
#elif defined(_arm64_)
typedef uint8x16_t	VEC_T; // 128bit = 16byte
#else
#endif

// Encryption definitions
#define NUM_MTRX_KEYS		(32 / sizeof(MOD_T)) // # of square matrix keys
#define NUM_BETA_KEYS		3 // # of K_beta keys
#define SIMD_ENCRYPT_SIZE	(32 * HNC_RANK)

// Misc definitions
#define CURRENT_VER		0 // Current version
#define DEFAULT_PORT		9025 // Default port
#if !defined(PORT)
#define PORT			DEFAULT_PORT // Port
#endif
#define CONF_FILE_STANDARD	"/usr/local/etc/ssltest.conf" // Config file
#define CONF_FILE_LOCAL		"./ssltest.conf" // Config file
#define TMPF_TEMPLATE		".tmp.XXXXXX" // Tmplate for .tmp.XX file
#define HOSTNAME_LEN		256 // Max length of hostname
#define MAX_ERRMSG_LEN		256 // Max error message len
#define MAX_COM_ARGS		256
#define MAX_SERVERS		64
#ifdef HNC_RANK
#define GEN_DAT_SIZE		(HNC_RANK * 1024 * 1024) // General data size
						  // Do not change 1024 * 1024
#else
#define GEN_DAT_SIZE		(4 * 1024 * 1024) // General data size
						  // Do not change 1024 * 1024
#endif
#define SEND_DAT_SIZE		(GEN_DAT_SIZE >> 1) // Data size to send
#define RECV_DAT_SIZE		SEND_DAT_SIZE // Same as SEND_DAT_SIZE
#define MAX_PADDING_SIZE	(HNC_RANK * sizeof(MOD_T) - 1)
						// Max padding size

#define BENCH_ENC_DEC_REPEAT	6000 // Times to repeat enc/dec in
				     // BenchEncDecSpeed()

#if defined(_arm64_)
#if defined(_MSQUIC_HNC_)
#define SEND_REPEAT		2400 // Times to repeat sending SEND_DAT_SIZE
#else
#define SEND_REPEAT		40000 // Times to repeat sending SEND_DAT_SIZE
#endif
#else // __AVX2__
#if defined(_MSQUIC_HNC_)
#define SEND_REPEAT		3000 // Times to repeat sending SEND_DAT_SIZE
#else
#define SEND_REPEAT		50000 // Times to repeat sending SEND_DAT_SIZE
#endif
#endif // _arm64_

#define DEFAULT_USERNAME	"hncsl" // Default username
#define DEFAULT_SERVER_NAME	"localhost" // Default server name
#define TMP_DIR			"/tmp" // Tmp dir

// Certification
#define CERT_PEM		"../../common/cert.pem"
#define PRIVKEY_PEM		"../../common/key.pem"

// Send/recv buf size
#if defined(__linux__)
#define SNDRCV_BUFSIZ		(1 << 18) // Sock buf size for send/recv
#define SND_BUFSIZ		SNDRCV_BUFSIZ // Sock buf size for sending
#define RCV_BUFSIZ		SNDRCV_BUFSIZ // Sock buf size for sending
#elif defined(__FreeBSD__) // (1 << 17) seems to be fstest with 10Gbps
#define SNDRCV_BUFSIZ		(1 << 17) // Sock buf size for sending
#define SND_BUFSIZ		SNDRCV_BUFSIZ // Sock buf size for sending
#define RCV_BUFSIZ		SNDRCV_BUFSIZ // Sock buf size for sending
#endif

// Dirs
#define ROOT_DIR	"/usr/local/hncsl" 	 // Root dir
#define ROOT_DIR_LEN	strlen(ROOT_DIR) // Length of AUTH_DIR

// Some tweaks for Linux
#if defined(__linux__)
#define EDOOFUS	EPERM
#define EFTYPE	EILSEQ
#endif

// HHash
typedef uint64_t	HHash; // Common hash size

// SHA
#define SHA256_LEN	32

// Program type
typedef enum {
	PROG_HNCSL, PROG_HNCSLD, PROG_NUM
} Prog;


/*********************************************************************
	Config parm 
*********************************************************************/

// Global configuration parms
typedef struct {
	u_short	port; // Port
	char	port_s[256]; // Port string
	u_short	ssl_port; // SSL port
	char	uid[MAXLOGNAME]; // Uid
	bool	ssl; // Use SSL or not
} ConfigS;


/*********************************************************************
	Host info
*********************************************************************/

// Flags for HInfB.flg
#define HINFB_ME	1 // This host is me
#define HINFB_CL	(1 << 1) // This host is client
#define HINFB_SV	(1 << 2) // This host is server
#define HINFB_DEAD	(1 << 3) // This host is dead or inaccessible
#define HINFB_ADD	(1 << 4) // This host is to be newly added
#define HINFB_DEL	(1 << 5) // This host is to be deleted

// Basic host info
typedef struct {
	char		name[HOSTNAME_LEN]; // Host name
	HHash           hash; // Hash code
	struct addrinfo	*addr; // IP addresses
	uint64_t	flg; // Flags: see above
} HInfB;


/******* Host info for connection *******/
// Host status for HInf.status
enum {HOST_DEAD, HOST_CONNECTING, HOST_ALIVE};

// Flags for HInf.flg
#define HINF_OK		1 // Host is alive
#define HINF_RCVREPLY	(1 << 1) // Receive reply
#define HINF_DEL	(1 << 2) // To be deleted

// Host info for connection
typedef struct {
	const char	*name; // Hostname
	const char	*chName; // Name for CH
	int		sock; // Socket
	int		status; // Status: see above host status HOST_*
	int		err;
	uint32_t	packet; // Packet #
	uint32_t	flg; // See above HINF_*
	ssize_t		sent; // Size of sent data
	struct timespec	resTime; // Response time
	HInfB		*hInfB; // Corresponding HInfB
} HInf;

/*********************************************************************
	libevent arg
*********************************************************************/

// Structure for common libevent argument
typedef struct {
	HInf		*hInf;
	const char	*path;
	void		*data;
	int		opt;
} EvArg;


/*********************************************************************
	Varibales
*********************************************************************/

#ifdef _MAIN_PROGRAM_
#define EXTERN
#else
#define EXTERN extern
#endif

// Command line arguments
EXTERN int		Argc;
EXTERN char		**Argv; // Args
EXTERN int		Optind;
EXTERN struct passwd	*Pwd;
EXTERN const char	*HomeDir; // Home dir
EXTERN char		CertPEM[PATH_MAX]; // Cert PEM
EXTERN char		PrivKeyPEM[PATH_MAX]; // Private key PEM

// Etc
EXTERN char		Program[PATH_MAX]; // Command name 
EXTERN char		ProgramPath[PATH_MAX]; // Program path 
EXTERN int		Command; // Command: see COM_GET, COM_PUT... above
EXTERN uid_t		MyUid; // My uid
EXTERN char		MyHostname[4096]; // My hostname
EXTERN in_addr_t	LocalHostAddr; // Local host IP address
EXTERN struct addrinfo	*MyAddr; // My IP addresses

#undef EXTERN

#endif // _HNCSL_COMMON_H_
