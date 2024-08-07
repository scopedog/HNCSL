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

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/ssl.h>


#ifdef __cplusplus
#define EXTERNC	extern "C"
#else
#define EXTERNC
#endif

/*********************************************************************
	Boolean
*********************************************************************/

typedef char	MyBool;
#ifndef	True
#define True	1
#endif
#ifndef	False
#define False	0
#endif


/*********************************************************************
	Private error messages
*********************************************************************/

#ifdef _DO_NOT_USE_PRIVATE_ERROR_
#define EPRIVSTART		10000 // Beginning of private error numbers 
#define ENOTFILE		EACCES // Not a file 
#define ETOOFEWSVALV		EPERM // Too few servers are alive
#define ETOOFEWSVENT		EIO // Too few servers have file/directory
#define EINCONSIST		EINVAL // Files are inconsistent 
#else
#define EPRIVSTART		10000 // Beginning of private error numbers 
#define ENOTFILE		10001 // Not a file 
#define ETOOFEWSVALV		10002 // Too few servers are alive
#define ETOOFEWSVENT		10003 // Too few servers have file/directory
#define EINCONSIST		10004 // Files are inconsistent 
#endif

#ifdef _UTIL_MAIN_
/******* Error strings *******/
static char *ErrStr[] =
{
	"",
	"Not a file",
	"Too few servers are alive",
	"Too few servers have file/directory",
	"Files are inconsistent",
};
#else
#define	strerror	MyStrError
EXTERNC char	*MyStrError(int);
#endif // _UTIL_MAIN_ 


#if defined(__linux__)
/*********************************************************************
	Some definitions for Linux
*********************************************************************/

// Chmod
#define lchmod	chmod

// Time
#if !defined(TIMEVAL_TO_TIMESPEC)
#define TIMEVAL_TO_TIMESPEC(tv, ts)                                     \
	do {                                                            \
	(ts)->tv_sec = (tv)->tv_sec;                            \
		(ts)->tv_nsec = (tv)->tv_usec * 1000;                   \
	} while (0)
#endif
#if !defined(TIMESPEC_TO_TIMEVAL)
#define TIMESPEC_TO_TIMEVAL(tv, ts)                                     \
	do {                                                            \
		(tv)->tv_sec = (ts)->tv_sec;                            \
		(tv)->tv_usec = (ts)->tv_nsec / 1000;                   \
	} while (0)
#endif
#endif



/*******************************************************************************
 	Structures 
*******************************************************************************/

// BitSet structure
typedef struct {
	size_t		size;	// Bit size
	unsigned int	*bit;	// Integers used for bit set
	int		sem;	// Semaphore ID
	size_t		sel;	// # of selected bits for BitSetSelect* 
} BitSet;

#if 1
// Linked list
typedef struct _LEnt	LEnt;
struct _LEnt {
	void	*data;	/* Data */
	LEnt	*prev;	/* Previous */
	LEnt	*next;	/* Next */
};

typedef struct {
	LEnt	*head;
	LEnt	*tail;
	LEnt	*last;
} LList;
#endif

// StrList
typedef struct {
	char	*list;
	size_t	size; // Allocated size of 'list'
	size_t	len; // Current length of string list in 'list'
} StrList;

// PtLock
typedef struct {
	int		numR; // # of readers
	int		numW; // # of writers
	int		numWW; // # of waiting writers
	pthread_mutex_t	mutex;
	pthread_cond_t	condR;
	pthread_cond_t	condW;
} PtLock;

/*******************************************************************************
 	Variables 
*******************************************************************************/

#ifdef _UTIL_MAIN_
#define EXTERN
#else
#define EXTERN extern
#endif

EXTERN int	Debug; // Debug flag
EXTERN int	Daemon; // Daemon flag
EXTERN int	Verbose; // Verbos flag

#undef	EXTERN

/*******************************************************************************
 	Utility functions 
*******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif
#if 0
/* Output error message and exit */
void	ErrorExit(const char *, ...);

/* Put perror's message and exit */
void	PerrorExit(char *);
#endif

/* Output debug message */
void	DebugMsg(const char *, ...);

/* Output verbose message */
void	VerboseMsg(const char *, ...);

// Return end of string
char	*EndOfStr(const char *, size_t);
char	*EndOfStrE(const char *, const char *);

/* Trim (delete unncessary spaces, tabs from) string */
char	*TrimString(char *);

// Remove '/' from end of path
void	RmTailSlash(char *path);

// Integer to binary string: Caution! Not thread safe!
const char	*IntToBinary(int);

// Count numbers (0-9) in string and copy only numbers if necessary
int	CountNumbers(const char *, char *, size_t);

// Calculate rate of English characters in string
double	EnglishRate(const char *);

/* Save pid */
int	SavePid(char *);

#if 0
/* Daemonize */
int	Daemonize(char *);
#endif

/* Read / write all */
ssize_t	ReadAll(int, void *, size_t);
ssize_t	WriteAll(int, void *, size_t);

// Read with timeout
ssize_t	ReadTimeout(int, void *, size_t, int);
#ifdef __cplusplus
}
#endif


/*****************************************************************************
	Network functions
*****************************************************************************/

//const char	*GetHostByAddr(struct sockaddr_in *);
void		ShowGetaddrinfoErr(const char *, int, const char *);
MyBool		IpAddrMatchAddrinfo(struct addrinfo *, struct addrinfo *);
in_addr_t	GetIp4Addr(struct addrinfo *);
int		GetMyAddrInfo(struct addrinfo **);

/*****************************************************************************
	Bit Set functions
*****************************************************************************/

// Create bit set
BitSet	*BitSetCreate(size_t);

// Duplicate bit set
BitSet	*BitSetDup(BitSet *);

// Destroy BitSet
void	BitSetDestroy(BitSet *);

// Set all bits 0 or 1
int	BitSetSetAll(BitSet *, int);

// Set one bit 0 or 1
int	BitSetSet(BitSet *, int, int);

// Check if the specified bit is set
int	BitSetIsSet(BitSet *, int);

// Check if the bitset is empty
int	BitSetIsEmpty(BitSet *);

// Check if all the bits are set 1
int	BitSetIsAllSet(BitSet *);

// Inverse all bits
void	BitSetInverseAll(BitSet *);

// Copy BitSet
int	BitSetCopy(BitSet *, BitSet *);

// Initialize for selecting 'sel' bits
int	BitSetSelectInit(BitSet *, int);

// Select next 'sel' bits
int	BitSetSelectNext(BitSet *);

// Show all bits for debug
void	BitSetShowAll(BitSet *);

/*****************************************************************************
	pthread
*****************************************************************************/

/* Pthread's synchronization */
void	PthreadSynchronize(pthread_cond_t *, pthread_mutex_t *, int *, int);

/*****************************************************************************
	Random generator
*****************************************************************************/

/* Random functions */
#if 0
unsigned char	MyRandUChar(void);
int		MyRandInt(int, int);
#endif
uint16_t	MyRand16(void);

/*****************************************************************************
	Matrix
*****************************************************************************/

/* Matrix */
int		*AllocVector(int);
double		*AllocVectorDouble(int);
void		FreeVector(void *);
int		**AllocMatrix(int, int);
uint16_t	**AllocMatrixUint16(int, int);
double		**AllocMatrixDouble(int, int);
void		FreeMatrix(void *);
void		ShowMatrixUint16(uint16_t **, int, int);

/* Calculate quadratic form -- x'Ax */
double	QuadForm(double *, int **, int);

/* Calculate quadratic matrix form -- X'AX */
#ifdef _UTIL_C_USE_FLOAT_QUAD_MATRIX_
double	**QuadMatrix(double **, int **, int, int);
#else
int	**QuadMatrix(int **, int **, int, int);
#endif

/*****************************************************************************
	Graph
*****************************************************************************/

/* Shortest paths */
void	AllShortestPaths(int **, int **, int);
void	AllShortestPathsDouble(double **, double **, int);

/* Is a graph connected? */
int	IsGraphConnected(int **, int);

/*****************************************************************************
	Linked list
*****************************************************************************/

LList	*LListCreate(size_t);
LEnt	*LListPrepend(LList *, void *);
LEnt	*LListAppend(LList *, void *);

/*****************************************************************************
	Network
*****************************************************************************/

#ifdef _WIN32
#define MyRecv	recv
#define MySend	send
#else // For Unix
#define	SOCKET	int
#endif // _WIN32

ssize_t	SendAll(int, const void *, int, int);
ssize_t	RecvAll(int, void *, int, int);
ssize_t	RecvTimeout(int, void *, size_t, int);
int	RecvUnnecessaryMsg(int, size_t);
int	SockSetTcpNoDelay(int, bool);
void	SockSetNonBlock(SOCKET);
void	SetSndRcvBufSiz(int, int);
void	SetSndBufSiz(int, int);
void	SetRcvBufSiz(int, int);

// IPv4, v6 functions
in_addr_t	V4MappedV6Addr(struct sockaddr_storage *);
void		*get_in_addr(struct sockaddr *);

/*****************************************************************************
	Pipe
*****************************************************************************/

enum {PIPE_TO_MAIN, PIPE_TO_CHILD, PIPE_NUM};

int	MyPipeSend(SOCKET, void *, int);
int	MyPipeRecv(SOCKET, void *, int);
int	ThreadPipes(SOCKET [][2]);
void	ThreadPipesClose(SOCKET [][2]);
const char	*SockErrorMessage(int);
const char	*SockError(void);
/*
void	SockBlock(SOCKET);
void	SockNonBlock(SOCKET);
*/

#ifdef _WIN32
int	MyPipe(SOCKET fd[]);
int	MySend(SOCKET, void *, int, int);
int	MyRecv(SOCKET, void *, int, int);
#ifdef	pipe
#undef	pipe
#define pipe	MyPipe
#endif
#else // Unix
#define MyPipe	pipe
#define closesocket	close
#endif // _WIN32

#if defined (__cplusplus)
extern "C" {
#endif

/*****************************************************************************
	String list
*****************************************************************************/

char	*StrListSearch(StrList *, const char *);
int	StrListAppend(StrList *, const char *);
int	StrListAppendList(StrList *, StrList *);
int	StrListMerge(StrList *, StrList *);
int64_t	StrListCount(StrList *);
void	StrListShow(StrList *);
void	StrListFree(StrList *);

/*****************************************************************************
	Hash
*****************************************************************************/

int32_t		MyHash(const char *, int); // Too simple
uint32_t	MyPrime2cHash(const char *, unsigned int len);
uint64_t	MyHash64(const char *, size_t);
uint64_t	siphash24(const void *, unsigned long, const char[16]);
void		ShowHash(uint8_t *, size_t);

/*****************************************************************************
	Misc
*****************************************************************************/

char	*Dirname(char *);
int	CheckDir(const char *);
int	CopyFile(const char *, const char *);
int	RecursiveMkdir(const char *, mode_t, uid_t, gid_t);
int	RecursiveRm(const char *);
int	RecursRmCheckSock(const char *, int);
StrList	*DirGetEntriesAll(const char *);
int	Utimens(const char *, const struct timespec *);
int	Futimens(int, const struct timespec *);
StrList	*DirStrList(const char *);
void	GetProgramName(const char *, char *, size_t);
int	ExecAutoPath(const char *, char *const []);
void	RestartProgram(const char *, char * const *);

/*****************************************************************************
	Memory allocation test
*****************************************************************************/

void	*Malloc(size_t);
void	Free(void *);
/*
#define malloc	Malloc
#define free	Free
*/

/*****************************************************************************
	PtLock - Read/write lock for pthread
*****************************************************************************/

int	PtLockInit(PtLock *);
void	PtLockDestroy(PtLock *);
int	PtLockLockR(PtLock *);
int	PtLockUnlockR(PtLock *);
int	PtLockLockW(PtLock *);
int	PtLockUnlockW(PtLock *);


/*****************************************************************************
	File and memory
*****************************************************************************/

int	ReadFile(const char *, uint8_t **, size_t *);
int	WriteFile(const char *, const uint8_t *, size_t);

#if defined (__cplusplus)
}
#endif

/*****************************************************************************
	For Linux or FreeBSD >= 12
*****************************************************************************/

#if defined(__linux__) || (__FreeBSD__ >= 12)
char	*basename_r(const char *path, char *);
#endif
#if defined(__linux__)
void	strmode(int mode, char *p);
#endif

/*****************************************************************************
	Base64
*****************************************************************************/

uint8_t *base64_encode(const unsigned char *, size_t, size_t *);
uint8_t *base64_decode(const unsigned char *, size_t, size_t *);

/*****************************************************************************
	SSL
*****************************************************************************/

int	SSL_read_all(SSL *, void *, int);

#if 0 // XML
/*****************************************************************************
	XML
*****************************************************************************/

size_t	ConvTextToXML(const char *, char *, size_t);
int	FormatTextXML(char **, size_t *);
#endif // XML

void	ShowBytes(const uint8_t *, size_t);

#endif /* _UTIL_H_ */
