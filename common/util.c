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

/******************************************************************************
*
*	PROGRAM  : util.c
*	LANGUAGE : C
*	REMARKS  : Miscellaneous convenient functions 
*	AUTHOR   : Hiroshi Nishida
*
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <limits.h>
#include <float.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <fcntl.h>
#include <libgen.h>
#include <fts.h>
#include <dirent.h>
#include <ifaddrs.h> // Must be before <net/if.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/utsname.h>
//#include <sys/event.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#define	_UTIL_MAIN_
#include "util.h"
#undef	_UTIL_MAIN_
#include "log.h"
//#include "mt19937ar.h"

/*****************************************************************************
	Parameters
*****************************************************************************/

extern int	Debug;


/*********************************************************************
	Private error messages
*********************************************************************/

// Return error message
char *
MyStrError(int e)
{
	if (e < EPRIVSTART)
		return strerror(e);
	else
		return ErrStr[e - EPRIVSTART];
}


/*****************************************************************************
	Utility functions
*****************************************************************************/

/* Output debug message */
void
DebugMsg(const char *fmt, ...)
{
	va_list	ap;

	if (!Debug)
		return;

	fputs("DEBUG: ", stdout);
	va_start(ap, fmt);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
	vfprintf(stdout, fmt, ap);
#pragma clang diagnostic pop
	va_end(ap);

	fflush(stdout);
}

/* Output verbose message */
void
VerboseMsg(const char *fmt, ...)
{
	va_list	ap;

	if (!Verbose && !Debug)
		return;

	va_start(ap, fmt);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
	vfprintf(stdout, fmt, ap);
#pragma clang diagnostic pop
	va_end(ap);

	fflush(stdout);
}

// Go to end of string
char *
EndOfStr(const char *str, size_t size)
{
	char	*p = (char *)str;
	size_t	s = 0;

	while (*p != '\0' && s < size) {
		p++;
		s++;
	}

	return p;
}

// Go to end of string - another version
char *
EndOfStrE(const char *str, const char *end)
{
	char	*p = (char *)str;

	while (*p != '\0' && p < end) {
		p++;
	}

	return p;
}

/* Trim string */
char *
TrimString(char *str)
{
	unsigned char	*p; /* There was a reason why I had to use 'unsigned'
			       here, but I forgot it. Probably, it was
			       necessary for UTF-8 strings. */

	/* Change '\n' to '\0' because some OSs like FreeBSD don't add '\0'
	   at the end of string retrieved by fgets() */
	if ((p = (unsigned char *) strrchr(str, '\n')) != NULL)
		*p = '\0';

	p = (unsigned char *) strrchr(str, '\0');
	for (--p; isspace((int) *p) && p >= (unsigned char *) str; p--)
		*p = '\0';

	for (p = (unsigned char *) str; isspace((int) *p) && *p != '\0'; p++);

	/* Return the pointer to trimmed string */
	return (char *) p;
}

// Remove '/' from end of path
void
RmTailSlash(char *path)
{
	char	*p;

	// Check if path ends with '/'
	if ((p = strrchr(path, '/')) != NULL) {
		if (p[1] == '\0') { // path ends with '/'
			do {
				*p = '\0';
				p--;
			} while (*p == '/' && p >= path);
		}
	}
}

// Integer to binary string: Caution! Not thread safe!
const char *
IntToBinary(int x)
{
	static char	b[256];
	unsigned int	z = 1 << (sizeof(int) * 8 - 1);

	b[0] = '\0';

	for (; z != 0; z >>= 1) {
		strcat(b, (x & z) ? "1" : "0");
	}

	return b;
}

// Count numbers (0-9) in string
int
CountNumbers(const char *str, char *digit, size_t digit_size)
{
	char		c;
	const char	*p;
	size_t		count = 0;

	for (p = str; ; p++) {
		c = *p;
		if (isdigit(c)) {
			if (digit != NULL && count < digit_size) {
				digit[count] = c;
			}
			count++;
		}
		else if (c == '\0') {
			if (digit != NULL) {
				digit[(count < digit_size) ?
					count : digit_size - 1] = '\0';
			}
			break;
		}
	}

	return count;
}

// Calculate rate of English characters in string
double
EnglishRate(const char *str)
{
	char		c;
	const char	*p;
	size_t		count_en, count_jp, count;

	count_en = count_jp = 0;
	for (p = str; ; p++) {
		c = *p;

		if (c == '\0') {
			break;
		}
		else if (c < 0) {
			count_jp++;
		}
		else if (!isspace(c)) {
			count_en++;
		}
	}
/*
printf("Len = %ld\n", p - str);
fflush(stdout);
*/

	count_jp /= 3; // One char per 3 bytes
	count = count_en + count_jp;
	if (count == 0) {
		return 0;
	}
	else {
		return (double)count_en / (double)count;
	}
}

/* Save pid */
int
SavePid(char *pid_file)
{
	pid_t	pid = getpid();
	FILE	*fp;

	/* Remove existing pid_file */
	remove(pid_file);

	/* Open */
	if ((fp = fopen(pid_file, "w")) == NULL) {
		fprintf(stderr, "Error: SavePid: fopen: %s", strerror(errno));
		return -1;
	}

	/* chmod */
	fchmod(fileno(fp), S_IRUSR | S_IWUSR);

	/* Save */
	fprintf(fp, "%d", (int) pid);
	fclose(fp);

	return 0;
}

#if 0
/* Daemonize */
int
Daemonize(char *work_dir)
{
#define	MAXFD	64
	pid_t	pid;
	int	i;

	/* Fork */
	if ((pid = fork()) < 0)
		PerrorExit("Error: fork() at Daemonize()");
	else if (pid != 0)
		exit(0);	/* This is a parent process and quits */

	/* Child process continues */
	setsid();		/* Become session leader */

	signal(SIGHUP, SIG_IGN);

	/* Fork again */
	if ((pid = fork()) < 0)
		PerrorExit("Error: second fork() at Daemonize()");
	else if (pid != 0)
		exit(0);	/* This is a parent process and quits */

	/* Chdir to work dir */
	if (work_dir != NULL) {
		if (chdir(work_dir) == -1) {
			PerrorExit("Error: chdir");
		}
	}

	/* Close fd */
	for (i = 0; i < MAXFD; i++)
		close(i);
#undef	MAXFD

	return 0;
}
#endif

//long a,b,c; // randomly assigned 64-bit values

/* Read all */
ssize_t
ReadAll(int fd, void *buf, size_t size)
{
	uint8_t	*p = (uint8_t *)buf;
	size_t	read_size = 0;
	ssize_t	ret;

	do {
		 if ((ret = read(fd, p + read_size, size - read_size)) <= 0)
			return ret;

		read_size += ret;
	} while (read_size < size);

	return read_size;
}

/* Write all */
ssize_t
WriteAll(int fd, void *buf, size_t size)
{
	uint8_t	*p = (uint8_t *)buf;
	size_t	write_size = 0;
	ssize_t	ret;

	do {
		 if ((ret = write(fd, p + write_size, size - write_size)) <= 0)
			return ret;

		write_size += ret;
	} while (write_size < size);

	return write_size;
}

/* Read with timeout -- select() version
   Returned values:
	-2: Error with select() or read()
	-1: read() returned 0, ie, fd was closed
	 0: Timeout at select()
	Else: returned value of read() */
ssize_t
ReadTimeout(int sock, void *data, size_t len, int tmout_msec)
{
	int		ret;
	ssize_t		_ret;
	div_t		d;
	struct timeval	tv;
	fd_set		fdset;

	/* Set timeout */
	if (tmout_msec) {
		d = div(tmout_msec, 1000);
		tv.tv_sec = d.quot;
		tv.tv_usec = d.rem * 1000;
	}

	/* Set socket */
	FD_ZERO(&fdset);
	FD_SET(sock, &fdset);

	/* Select */
	ret = select(sock + 1, &fdset, NULL, NULL, tmout_msec ? &tv : NULL);
	if (ret < 0) { /* Error */
		//Log("Error: %s: select: %s", __func__, strerror(errno));
		return -2;
	}
	else if (ret == 0) { /* Timeout */
		return 0;
	}

	/* Recieve data */
	_ret = ReadAll(sock, data, len);
	if (_ret < 0) { /* Error */
		//Log("Error: %s: ReadAll: %s", __func__, strerror(errno));
		return -2;
	}
	else if (_ret == 0) // Closed
		return -1;
	else
		return _ret;
}

/*****************************************************************************
	Network functions
*****************************************************************************/

#if 0
/* Get hostmane by address */
const char *
GetHostByAddr(struct sockaddr_in *addr)
{
	struct hostent	*host;

	if ((host = gethostbyaddr(&addr->sin_addr.s_addr, sizeof(in_addr_t),
				  AF_INET)) == NULL)
		return "";

	return (const char *)host->h_name;
}
#endif

// Show getaddrinfo error message
void
ShowGetaddrinfoErr(const char *func, int err, const char *hostname)
{
	if (func != NULL) {
		if (err == EAI_SYSTEM) {
			Log("Error: %s: getaddrinfo %s: %s",
				func, hostname, strerror(errno));
		}
		else {
			Log("Error: %s: getaddrinfo %s: %s",
				func, hostname, gai_strerror(err));
			errno = EPERM;
		}
	}
	else {
		if (err == EAI_SYSTEM) {
			Log("Error: getaddrinfo %s: %s",
				hostname, strerror(errno));
		}
		else {
			Log("Error: getaddrinfo %s: %s",
				hostname, gai_strerror(err));
			errno = EPERM;
		}
	}
}

// Compare 2 addrinfo and return True if IP addresses are identical
MyBool
IpAddrMatchAddrinfo(struct addrinfo *addr1, struct addrinfo *addr2)
{
	int		ai_family;
	struct addrinfo	*ad1, *ad2;
	MyBool		ipv6_exists = False, ipv4_match = False;

	// Scan addr info
	for (ad1 = addr1; ad1 != NULL; ad1 = ad1->ai_next) {   
		for (ad2 = addr2; ad2 != NULL; ad2 = ad2->ai_next) {   
/*
			if (ad1->ai_family != ad2->ai_family ||
			    ad1->ai_socktype != ad2->ai_socktype) {
*/
			// Check IP family
			ai_family = ad1->ai_family;
			if (ai_family != ad2->ai_family) {
				continue;
			}

			// Check if IPv6
			if (ai_family == AF_INET6) {
				ipv6_exists = True;
			}

			// Compare addresses
			if (memcmp(ad1->ai_addr, ad2->ai_addr,
					ad1->ai_addrlen) == 0) {
				// Identical
/* Debug
				{
				char	addrS1[64], addrS2[64];

				printf("ad1: %s, ad2: %s\n",
					inet_ntop(ad1->ai_family,
						get_in_addr(ad1->ai_addr),
						addrS1, sizeof(addrS1)),
					inet_ntop(ad2->ai_family,
						get_in_addr(ad2->ai_addr),
						addrS2, sizeof(addrS2)));
				}
*/
				// Return true if protocol is IPv6
				if (ai_family == AF_INET6) {
					return True;
				}
				else {
					ipv4_match = True;
				}
			}
		}
	}

	// OK, we have to kick out if v4 adds are same but v6 are different
	// We only return True only if !ipv6_exists && ipv4_match
	return (!ipv6_exists && ipv4_match) ? True : False;
}

// Compare addrinfo and struct sockaddr_storage and return True
// if IP addresses match
MyBool
IpAddrMatchSockaddr(struct addrinfo *addr1, struct sockaddr_storage *addr2)
{
	struct addrinfo	*ad1;
	sa_family_t	addr_family = addr2->ss_family;

	// Scan addr info
	for (ad1 = addr1; ad1 != NULL; ad1 = ad1->ai_next) {   
		// Check address family
		if (ad1->ai_family != addr_family) {
			continue;
		}
		// Check IP address
		else if (memcmp(ad1->ai_addr, addr2, ad1->ai_addrlen) == 0) {
			// Identical
			return True;
		}
	}

	// Could not find same IP address
	return False;
}

// Get IPv4 address from struct addrinfo *
in_addr_t
GetIp4Addr(struct addrinfo *addr)
{
	struct addrinfo	*ad;

	// Scan all addr info
	for (ad = addr; ad != NULL; ad = ad->ai_next) {   
		switch (ad->ai_family) {
		//case AF_INET6:
		case AF_INET: // Return first IPv4 address
			return ((struct sockaddr_in *)ad->ai_addr)
					->sin_addr.s_addr;
		default:
			continue;
		}
	}

	// Not found
	errno = EPERM;
	return 0;
}

// Get my addrinfo from NIC except for lo0
int
GetMyAddrInfo(struct addrinfo **myAddr)
{
	int		err = 0;
	struct ifaddrs	*if_addr = NULL, *ifa;
	struct sockaddr	*saddr;
	sa_family_t	sfmly;
	struct utsname	hname;
	struct addrinfo	hints, *addr = NULL, *_addr;
	struct addrinfo	*host_addr = NULL, *_haddr;
	char		addrBuf[256];
	MyBool		match;
#if defined(__linux__)
	size_t		slen;
#else
	uint8_t		slen;
#endif

	// Get address info from network interface
	if (getifaddrs(&if_addr) == -1) {
		Log("Error: %s: getifaddrs: %s", __func__, strerror(errno));
		err = errno;
		goto END;
	}

	// Initialize
	*myAddr = NULL;

	// Scan each address info
	for (ifa = if_addr; ifa != NULL; ifa = ifa->ifa_next) {
		// Check struct sockaddr
		saddr = ifa->ifa_addr;
		if (saddr == NULL) { // Skip no address
			continue;
		}

		// Check sa_family, skip non IP
		sfmly = saddr->sa_family;
		switch (sfmly) {
		case AF_INET:
#if defined(__linux__)
			slen = sizeof(struct sockaddr_in);
#endif
			break;
		case AF_INET6:
#if defined(__linux__)
			slen = sizeof(struct sockaddr_in6);
#endif
			break;
		default:
			continue;
		}

		//DebugMsg("ifa->ifa_name: %s\n", ifa->ifa_name);

		// Skip lo0
		if (strcmp(ifa->ifa_name, "lo0") == 0) {
			continue;
		}

		// Allocate and init addr
		if ((_addr = (struct addrinfo *)
				malloc(sizeof(struct addrinfo))) == NULL) {
			Log("Error: %s: malloc _addr: %s",
				__func__, strerror(errno));
			err = errno;
			goto END;
		}
		memset(_addr, 0, sizeof(struct addrinfo));

		// Set myAddr/ai_next
		if (*myAddr == NULL) {
			*myAddr = _addr;
		}
		else if (addr != NULL) {
			addr->ai_next = _addr;
		}
		addr = _addr;

		// Set sin family
		addr->ai_family = sfmly;

#if !defined(__linux__)
		// Set len of struct
		slen = addr->ai_addrlen = ifa->ifa_addr->sa_len;
#else
		addr->ai_addrlen = slen;
#endif

		// Alloc ai_addr and copy from ifa->ifa_addr
		if ((addr->ai_addr = (struct sockaddr *)malloc(slen))
				== NULL) {
			Log("Error: %s: malloc addr: %s",
				__func__, strerror(errno));
			err = errno;
			goto END;
		}
		memcpy(addr->ai_addr, ifa->ifa_addr, slen);

		// Debug - show interface and addr info
		if (Debug) {
			inet_ntop(sfmly, get_in_addr(addr->ai_addr), addrBuf,
				sizeof(addrBuf));
			DebugMsg("%s: IP Address %s, len = %d\n",
				ifa->ifa_name, addrBuf, slen);
		}
	}

	// Free if_addr
	if (if_addr != NULL) {
		freeifaddrs(if_addr);
	}

	// Get my host name
	if (uname(&hname) < 0) {
		// This happens in some cases
		Log("Warning: %s: uname: %s", __func__, strerror(errno));
		//err = errno;
		goto END;
	}
	//Log("My hostname: %s", hname.nodename);

	// Get my IP address from my host name
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	_addr = NULL;
	if ((err = getaddrinfo(hname.nodename, NULL, &hints, &host_addr))) {
		// This may happen
		ShowGetaddrinfoErr(__func__, err, hname.nodename);
		Log("Warning: %s: Couldn't obtain my IP address (%s)",
			__func__, hname.nodename);
		
		// We ingore this error
		err = 0;
		goto END;
	}

	// Check if each addr in host_addr is already included in myAddr
	for (_haddr = host_addr; _haddr != NULL; _haddr = _haddr->ai_next) {
		sfmly = _haddr->ai_family;
		match = False;
/* Debug
		inet_ntop(sfmly, get_in_addr(_haddr->ai_addr), addrBuf,
			sizeof(addrBuf));
		printf("IP Address: %s\n", addrBuf);
*/
		for (_addr = NULL, addr = *myAddr; addr != NULL;
				_addr = addr, addr = addr->ai_next) {
			// Check inet family first
			if (addr->ai_family != sfmly) {
				continue;
			}
			// Check if addresses are same
			else if (memcmp(_haddr->ai_addr, addr->ai_addr,
					_haddr->ai_addrlen) == 0) {
				// Identical
				match = True;
				break;
			}
		}

		// Append this addr to myAddr if not matched
//puts(match ? "Match" : "Not found");
		if (!match) {
			// Assume _addr is end of myAddr
			addr = _addr;

			// Allocate and init addr
			if ((_addr = (struct addrinfo *)
				malloc(sizeof(struct addrinfo))) == NULL) {
				Log("Error: %s: malloc _addr: %s",
					__func__, strerror(errno));
				err = errno;
				goto END;
			}
			memset(_addr, 0, sizeof(struct addrinfo));

			// Set myAddr/ai_next
			if (*myAddr == NULL) {
				*myAddr = _addr;
			}
			else if (addr != NULL) {
				addr->ai_next = _addr;
			}
			addr = _addr;

			// Alloc ai_addr
			if ((addr->ai_addr = (struct sockaddr *)
				malloc(sizeof(struct sockaddr_in6))) == NULL) {
				Log("Error: %s: malloc addr: %s",
					__func__, strerror(errno));
				err = errno;
				goto END;
			}

			// Set addr
			addr->ai_family = sfmly;
			addr->ai_addrlen = _haddr->ai_addrlen;
			memcpy(addr->ai_addr, _haddr->ai_addr,
				_haddr->ai_addrlen);
		}
	}

	// Debug - Check all my IP addresses
/*
	for (addr = *myAddr; addr != NULL; addr = addr->ai_next) {
		inet_ntop(addr->ai_family, get_in_addr(addr->ai_addr),
			addrBuf, sizeof(addrBuf));
		printf("ai_flags = %d, ai_family = %d, ai_socktype = %d, "
		       "ai_protocol = %d, ai_addrlen = %d, addr = %s, "
		       "ai_canonname = %s\n",
			addr->ai_flags, addr->ai_family, addr->ai_socktype,
			addr->ai_protocol, addr->ai_addrlen, addrBuf,
			addr->ai_canonname);
	}
*/

END:
	// Check error
	if (err) {
		// Free if_addr
		if (if_addr != NULL) {
			freeifaddrs(if_addr);
		}

		// Free myAddr
		if (*myAddr != NULL) {
			freeaddrinfo(*myAddr);
		}
		return -1;
	}
	else {
		errno = 0; // errno may be non-zero
		return 0;
	}
}

/*****************************************************************************
	Bit Set functions
*****************************************************************************/

// Create bit set
BitSet *
BitSetCreate(size_t size)
{
	int		num_of_int;
	unsigned int	*bit;
	//static int	sem_key = 12022;
	BitSet		*bitset;

#if 0	/* Since size_t is unsigned, we do not need to check this */
	/* Check size */
	if (size <= 0) {
		fprintf(stderr, "Error: BitSetCreate(): Wrong size: %d\n",
			size);
		return NULL;
	}
#endif

	/* Allocate BitSet */
#if 0	/* With mmap */	
	if ((bitset = (BitSet *) mmap(0, sizeof(BitSet), PROT_READ | PROT_WRITE,
	     MAP_ANON | MAP_SHARED, -1, 0)) == MAP_FAILED) {
		return NULL;
	}
#else	/* Use malloc */
	if ((bitset = (BitSet *) malloc(sizeof(BitSet))) == NULL) {
		return NULL;
	}
#endif

	/* Set size */
	bitset->size = size;

	/* Count how many integers are needed */
	num_of_int = (size - 1) / (sizeof(int) << 3) + 1;

	/* Allocate BitSet */
#if 0	/* Use mmap */	
	if ((bit = (unsigned int *) mmap(0, sizeof(unsigned int) * num_of_int,
	     PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0))
	     == MAP_FAILED) {
		return NULL;
	}
#else	/* Use malloc */
	if ((bit = (unsigned int *) malloc(sizeof(unsigned int) * num_of_int))
	     == NULL) {
		return NULL;
	}
#endif

	/* Set bit */
	bitset->bit = bit;

	/* Initialize bit -- set all bits false */
	bzero(bit, num_of_int * sizeof(int));

	/* Create semaphore */
/*
	bitset->sem = SemCreate((key_t) sem_key, 1);
	sem_key++;
*/

	/* Return */
	return bitset;
}

// Duplicate BitSet
BitSet *
BitSetDup(BitSet *src)
{
	int	i;
	BitSet	*bitset;

	bitset = BitSetCreate(src->size);

	for (i = (bitset->size - 1) / (sizeof(int) << 3); i >= 0; i--)
		bitset->bit[i] = src->bit[i];

	return bitset;
}

// Destroy BitSet
void
BitSetDestroy(BitSet *bitset)
{
	/* Free bit */
	free(bitset->bit);

	/* Free bitset */
	free(bitset);
}

/* Set all bits 0 or 1 */
int
BitSetSetAll(BitSet *bitset, int val)
{
	register int	i;
	unsigned int	set_val;

	/* Check val -- accept only 0 or 1 */
	switch (val) {
	    case 0:
	    case 1:
		break;
	    default:
		Log("Error: BitSetSetAll(): Wrong set val: %d", val);
		errno = EPERM;
		return -1;
	}

	/* Set set_val */
	set_val = val ? UINT_MAX : 0;

	/* Enter critical section for bit */
	//SemLock(bitset->sem, 0);

	/* Set all bits */
	for (i = (bitset->size - 1) / (sizeof(int) << 3); i >= 0; i--)
		bitset->bit[i] = set_val;

	/* Get out of critical section for bit */
	//SemUnlock(bitset->sem, 0);

	return 0;
}

// Set one bit 0 or 1
int
BitSetSet(BitSet *bitset, int index, int val)
{
	div_t	d;

	/* Check val -- accept only 0 or 1 */
	switch (val) {
	    case 0:
	    case 1:
		break;
	    default:
		Log("Error: BitSetSet(): Wrong set val: %d", val);
		errno = EPERM;
		return -1;
	}

	/* Check index */
	if (index < 0 || index >= (int)bitset->size) {
		Log("Error: %s: Wrong index: %d", __func__, index);
		errno = EPERM;
		return -1;
	}

	/* Calculate real index */
	d = div(index, sizeof(int) << 3);

	/* Enter critical section for bit */
	//SemLock(bitset->sem, 0);

	/* Set val */
	if (val) /* Set 1 */
		bitset->bit[d.quot] |= 1 << d.rem;
	else /* Set 0 */
		bitset->bit[d.quot] &= UINT_MAX ^ (1 << d.rem);

	/* Get out of critical section for bit */
	//SemUnlock(bitset->sem, 0);

	return 0;
}

// Clear all bits -- same as BitSetSetAll(bs, 0)
void
BitSetClearAll(BitSet *bitset)
{
	register int	i;

	// Enter critical section for bit
	//SemLock(bitset->sem, 0);

	// Set all bits 0
	for (i = (bitset->size - 1) / (sizeof(int) << 3); i >= 0; i--)
		bitset->bit[i] = 0;

	// Get out of critical section for bit
	//SemUnlock(bitset->sem, 0);
}

// Check if the specified bit is set
int
BitSetIsSet(BitSet *bitset, int index)
{
	div_t	d;

	/* Check index */
	if (index < 0 || index >= (int)bitset->size) {
		Log("Error: BitSetIsSet(): Wrong index: %d", index);
		errno = EPERM;
		return 0;
	}

	/* Calculate real index */
	d = div(index, sizeof(int) << 3);

	/* Check bit val and return */
	return bitset->bit[d.quot] & (1 << d.rem);
}

// Check if the bitset is empty
int
BitSetIsEmpty(BitSet *bitset)
{
	register int	i, rem, size = (int)bitset->size;
	unsigned int	b;

	/* Check bit[i] except for the last bitset */
	for (i = 0; i < (size - 1) / (int)(sizeof(int) << 3); i++) {
		/* If bit[i] != 0, return false */
		if (bitset->bit[i])
			return 0;
	}
	
	/* Check the last bitset */
	b = bitset->bit[i];
	rem = size % (int)(sizeof(int) << 3);
	if (rem) /* If the last bitset is not fully used */ 
		b &= (1 << rem) - 1;

	/* Check 0 or not */
	return !b;
}

// Check if the bits in the bitset are all set
int
BitSetIsAllSet(BitSet *bitset)
{
	register int	i, rem, size = bitset->size;
	unsigned int	b;

	/* Check bit[i] except for the last bitset */
	for (i = 0; i < (size - 1) / (int)(sizeof(int) << 3); i++) {
		/* If bit[i] != UINT_MAX, return false */
		if (bitset->bit[i] != UINT_MAX)
			return 0;
	}
	
	/* Check the last bitset */
	b = bitset->bit[i];
	rem = size % (int)(sizeof(int) << 3);
	if (rem) { /* If the last bitset is not fully used */ 
		b &= (1 << rem) - 1;

		return b == (1 << rem) - 1;
	}
	else
		return b == UINT_MAX;
}

// Inverse all bits
void
BitSetInverseAll(BitSet *bitset)
{
	register int	i, size = bitset->size;

	/* Inverse all bit */
	for (i = 0; i <= (size - 1) / (int)(sizeof(int) << 3); i++) {
		bitset->bit[i] = ~(bitset->bit[i]);
	}
}

// Initialize for selecting 'sel' bits
int
BitSetSelectInit(BitSet *bs, int sel)
{
	int	i;

	// Clear all bits
	BitSetClearAll(bs);

	// Save sel
	bs->sel = sel;

	// Set first 'sel' bits 1
	for (i = 0; i < sel; i++) {
		if (BitSetSet(bs, i, 1) == -1) { // Error
			Log("Error: %s: BitSetSet: %s",
				__func__, strerror(errno)); 
			return -1;
		}
	}

	return 0;
}

// Select next 'sel' bits
int
BitSetSelectNext(BitSet *bs)
{
	int64_t	sel = bs->sel;
	int64_t	idx, _sel, __sel, last_idx;

	for (_sel = 0; _sel < sel;) {
		// Find first bit
		last_idx = bs->size - _sel - 1;
		for (idx = last_idx; idx >= 0; idx--) {
			if (BitSetIsSet(bs, idx)) {
				break;
			}
		}

		// Check if idx was found
		if (idx < 0) { // Not found
			Log("Error: %s: No bit found", __func__); 
			errno = EPERM;
			return -1;
		}

		// Unset this idx
		BitSetSet(bs, idx, 0);

		// Next bit
		if (idx == last_idx) { // Reached end of bit for this _sel
			_sel++;
		}
		else {
			// Just set this idx 1 and return
			idx++;
			BitSetSet(bs, idx, 1);

			// Fill _sel bits after idx with 1
			for (__sel = 0; __sel < _sel; __sel++) {
				idx++;
				BitSetSet(bs, idx, 1);
			}

			return 0;
		}
	}

	// No more next selection
	return -1;
}

// Copy BitSet
int
BitSetCopy(BitSet *dst, BitSet *src)
{
	size_t	size = dst->size;

	// Compare sizes
	if (size != src->size) { // Different
		errno = EPERM;
		return -1;
	}

	// Copy
	memcpy(dst->bit, src->bit,
		((size - 1) / (sizeof(int) << 3) + 1) * sizeof(int));

	return 0;
}

// Show all bits for debug
void
BitSetShowAll(BitSet *bitset)
{
	int	i;
	size_t	size = bitset->size;

	for (i = size - 1; i >= 0; i--) {
		putchar(BitSetIsSet(bitset, i) ? '1' : '0');
	}
	putchar('\n');
}

/*****************************************************************************
	pthread functions
*****************************************************************************/

/* Synchronize among threads */
void
PthreadSynchronize(pthread_cond_t *cond, pthread_mutex_t *mutex, int *count,
		   int init_count)
{
	pthread_mutex_lock(mutex);
	(*count)--;

	if (*count)
		pthread_cond_wait(cond, mutex);
	else {
		pthread_cond_broadcast(cond);
		*count = init_count;
	}

	pthread_mutex_unlock(mutex);
}

#if 0
/*****************************************************************************
	Random generators
*****************************************************************************/

/* Random function -- unsigned char */
unsigned char
MyRandUChar(void)
{
	return (unsigned char) (genrand_int32() >> 24);
}

/* Generate an integer number between a and b (a < b) */
int
MyRandInt(int a, int b)
{
	int		c, ret;
	unsigned int	mask;

	c = b - a;
	if (c < 0) {
		fprintf(stderr, "Error: MyRandInt: a > b (%d > %d)\n", a, b);
		exit(EXIT_FAILURE);
	}
	else if (c == 0) {
		return a;
	}

	/* This implementation stinks */
	for (mask = INT_MIN; mask; mask >>= 1){
		if (mask & c)
			break;
	}

	--mask;
	mask = (mask << 1) | 1;

	//printf("%x\n", mask);

	do {
		ret = (int) genrand_int31() & mask;
	} while (ret > c);

	return ret + a;
}
#endif

// Generate random num with clock_gettime
uint16_t
MyRand16(void)
{
	struct timespec	ts;

	// Get current CPU time
	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint16_t)((ts.tv_sec ^ ts.tv_nsec) & 0xffff);
}

#if 1
/*****************************************************************************
	Vector/matrix functions
*****************************************************************************/

/* Allocate a vector with N elements */
int *
AllocVector(int N)
{
	int	*v;
	size_t	size;

	size = N * sizeof(int);
	if ((v = (int *)malloc(size)) == NULL) {
		return NULL;
	}

	bzero(v, size);

	return v;
}

/* Allocate a vector with N double elements */
double *
AllocVectorDouble(int N)
{
	double	*v;
	size_t	size;

	size = N * sizeof(double);
	if ((v = (double *)malloc(size)) == NULL) {
		return NULL;
	}

	bzero(v, size);

	return v;
}

/* Free a vector created by AllocVector */
void
FreeVector(void *v)
{
	free(v);
}

/* Allocate a N * M matrix */
int **
AllocMatrix(int N, int M)
{
	int	**A, i, *a;
	size_t	size;

	size = N * sizeof(int *);
	if ((A = (int **)malloc(size)) == NULL) {
		return NULL;
	}

	size = sizeof(int) * M * N;
	if ((a = (int *) malloc(size)) == NULL) {
		return NULL;
	}
	bzero(a, size);

	for (i = 0; i < N; i++) {
		A[i] = a;
		a += M;
	}

	return A;
}

/* Allocate a uint16_t N * M matrix */
uint16_t **
AllocMatrixUint16(int N, int M)
{
	uint16_t	**A, i, *a;
	size_t		size;

	size = N * sizeof(uint16_t *);
	if ((A = (uint16_t **) malloc(size)) == NULL) {
		return NULL;
	}

	size = sizeof(uint16_t) * M * N;
	if ((a = (uint16_t *)malloc(size)) == NULL) {
		return NULL;
	}
	bzero(a, size);

	for (i = 0; i < N; i++) {
		A[i] = a;
		a += M;
	}

	return A;
}

/* Allocate a N * M matrix whose entires are double */
double **
AllocMatrixDouble(int N, int M)
{
	int	i;
	double	**A, *a;
	size_t	size;

	size = N * sizeof(double *);
	if ((A = (double **)malloc(size)) == NULL) {
		return NULL;
	}

	size = sizeof(double) * M * N;
	if ((a = (double *)malloc(size)) == NULL) {
		return NULL;
	}
	bzero(a, size);

	for (i = 0; i < N; i++) {
		A[i] = a;
		a += M;
	}

	return A;
}

/* Free a matrix */
void
FreeMatrix(void *A)
{
	free(((void **) A)[0]);
	free(A);
}

void
ShowMatrixUint16(uint16_t **A, int N, int M)
{
	int	i, j;

	for (i = 0; i < N; i++) {
		for (j = 0; j < M; j++) {
			printf("%04x ", A[i][j]);
		}
		putchar('\n');
	}
}

/* Calculate quadratic form -- x'Ax */
double
QuadForm(double *x, int **A, int N)
{
	int		i, j, tmp_a;
	double		*tmp_v, tmp_x;
	long double	tmp_d;

	/* Allocate tmp_v */
	tmp_v = AllocVectorDouble(N);

	for (i = 0; i < N; i++) {
		tmp_d = 0.0;
		for (j = 0; j < N; j++) {
			tmp_x = x[j];
			tmp_a = A[j][i];
			if (tmp_a != 0 && tmp_x != 0.0)
				tmp_d += tmp_x * (double) tmp_a;
		}
		tmp_v[i] = (double) tmp_d;
	}

	tmp_d = 0.0;
	for (i = 0; i < N; i++) {
		tmp_x = x[i];
		if (tmp_x != 0.0)
			tmp_d += tmp_x * tmp_v[i];
	}

	FreeVector(tmp_v);

	return (double) tmp_d;
}

#ifdef _UTIL_C_USE_FLOAT_QUAD_MATRIX_
/* Calculate quadratic matrix multiplication -- X'AX - 
   Double precision version */
double **
QuadMatrix(double **X, int **A, int m, int n)
{
	int		i, j, k, tmp_a;
	double		**tmp_m1, **tmp_m2, tmp_x;
	long double	tmp_d;

	/* X is an n x m matrix, A is an n x n matrix */
	tmp_m1 = AllocMatrixDouble(m, n);
	tmp_m2 = AllocMatrixDouble(m, m);

	/* Calculate */
	for (i = 0; i < m; i++) {
		for (j = 0; j < n; j++) {
			tmp_d = 0.0;
			for (k = 0; k < n; k++) {
				tmp_x = X[k][i];
				tmp_a = A[k][j];
				if (tmp_x != 0.0 && tmp_a != 0)
					tmp_d += tmp_x * (double) tmp_a;
			}
			tmp_m1[i][j] = tmp_d;
		}
	}

	for (i = 0; i < m; i++) {
		for (j = 0; j < m; j++) {
			tmp_d = 0.0;
			for (k = 0; k < n; k++) {
				tmp_x = X[k][j];
				if (tmp_x != 0.0)
					tmp_d += tmp_m1[i][k] * tmp_x;
			}
			tmp_m2[i][j] = tmp_d;
		}
	}

	FreeMatrix(tmp_m1);

	return tmp_m2;
}
#else	/* Integer X version */
/* Calculate quadratic matrix multiplication -- X'AX */
int **
QuadMatrix(int **X, int **A, int m, int n)
{
	int	i, j, k, tmp_a, tmp, **tmp_m1, **tmp_m2, tmp_x;

	/* X is an n x m matrix, A is an n x n matrix */
	tmp_m1 = AllocMatrix(m, n);
	tmp_m2 = AllocMatrix(m, m);

	/* Calculate */
	for (i = 0; i < m; i++) {
		for (j = 0; j < n; j++) {
			tmp = 0;
			for (k = 0; k < n; k++) {
				tmp_x = X[k][i];
				tmp_a = A[k][j];
				if (tmp_x != 0 && tmp_a != 0)
					tmp += tmp_x * tmp_a;
			}
			tmp_m1[i][j] = tmp;
		}
	}

	for (i = 0; i < m; i++) {
		for (j = 0; j < m; j++) {
			tmp = 0;
			for (k = 0; k < n; k++) {
				tmp_x = X[k][j];
				if (tmp_x != 0)
					tmp += tmp_m1[i][k] * tmp_x;
			}
			tmp_m2[i][j] = tmp;
		}
	}

	FreeMatrix(tmp_m1);

	return tmp_m2;
}
#endif
 
#ifndef min
#define	min(a, b)	(((a) < (b)) ? (a) : (b))
#endif

/* Find the all shortest paths with Floyd-Warshall's algorithm */
void
AllShortestPaths(int **src, int **dst, int N)
{
	int	i, j, k, tmp1, tmp2;

	/* Copy src to dst i -- Note adjacency 0 is converted to INT_MAX */
	for (i = 0; i < N; i++) {
		for (j = 0; j < N; j++) {
			k = src[i][j];
			dst[i][j] = (k == 0 && i != j) ? INT_MAX : k;
		}
	}

	// Input data into dst, where dst[i][j] is the distance from i to j.
	for (k = 0; k < N; k++) {
		for (i = 0; i < N; i++) {
		    if ((tmp1 = dst[i][k]) == INT_MAX)
			continue;

		    for (j = 0; j < N; j++) {
			if ((tmp2 = dst[k][j]) == INT_MAX)
				continue;
			else {
				tmp2 += tmp1;
				if (dst[i][j] > tmp2) {
					dst[i][j] = tmp2;
				}
			}
		    }
		}
	}
}

/* AllShortestPaths's double precision version */
void
AllShortestPathsDouble(double **src, double **dst, int N)
{
	int	i, j, k;
	double	tmp1, tmp2;

	/* Copy src to dst i -- Note adjacency 0 is converted to INT_MAX */
	for (i = 0; i < N; i++) {
		for (j = 0; j < N; j++) {
			tmp1 = src[i][j];
			dst[i][j] = (tmp1 == 0.0 && i != j) ? DBL_MAX : tmp1;
		}
	}

	/* Input data into dst, where dst[i][j] is the distance from i to j. */
	for (k = 0; k < N; k++) {
		for (i = 0; i < N; i++) {
		    if ((tmp1 = dst[i][k]) == DBL_MAX)
			continue;

		    for (j = 0; j < N; j++) {
			if ((tmp2 = dst[k][j]) == DBL_MAX)
				continue;
			else {
				tmp2 += tmp1;
				if (dst[i][j] > tmp2) {
					dst[i][j] = tmp2;
				}
			}
		    }
		}
	}
}

/* Check if a graph is connected */
int
IsGraphConnected(int **G, int N)
{
	int	i, j, **D;

	/* Allocate the shortest path matrix D and get the shortes paths */
	D = AllocMatrix(N, N);
	AllShortestPaths(G, D, N);

	/* Check if the graph is connected */
	for (i = 0; i < N; i++) {
		for (j = 0; j < N; j++) {
			if (D[i][j] == INT_MAX) {
				//printf("%d, %d\n", i, j);
				FreeMatrix(D);
				return 0;
			}
		}
	}

	FreeMatrix(D);
	return 1;
}

#if 0
/* Dijkstra's algorithm */
#define GRAPHSIZE 2048
#define MAX(a, b) ((a > b) ? (a) : (b))

int e; /* The number of nonzero edges in the graph */
int n; /* The number of nodes in the graph */
long dist[GRAPHSIZE][GRAPHSIZE]; /* dist[i][j] is the distance between node i and j; or 0 if there is no direct connection */
long d[GRAPHSIZE]; /* d[i] is the length of the shortest path between the source (s) and node i */

void printD() {
	int i;

	for (i = 1; i <= n; ++i)
		printf("%10d", i);
	printf("\n");
	for (i = 1; i <= n; ++i) {
		printf("%10ld", d[i]);
	}
	printf("\n");
}

void dijkstra(int s) {
	int i, k, mini;
	int visited[GRAPHSIZE];

	for (i = 1; i <= n; ++i) {
		d[i] = INFINITY;
		visited[i] = 0; /* the i-th element has not yet been visited */
	}

	d[s] = 0;

	for (k = 1; k <= n; ++k) {
		mini = -1;
		for (i = 1; i <= n; ++i)
			if (!visited[i] && ((mini == -1) || (d[i] < d[mini])))
				mini = i;

		visited[mini] = 1;

		for (i = 1; i <= n; ++i)
			if (dist[mini][i])
				if (d[mini] + dist[mini][i] < d[i]) 
					d[i] = d[mini] + dist[mini][i];
	}
}
#endif
#endif

#if 1
/*****************************************************************************
	Linked list 
*****************************************************************************/

/* Create linked list */
LList *
LListCreate(size_t num_of_entries)
{
	size_t	i;
	LList	*llist;
	LEnt	*lent, *_lent, *_prev_lent;

	/* Allocate llist */
	if ((llist = malloc(sizeof(LList))) == NULL)
		return NULL;

	/* Allocate lent */
	if ((lent = malloc(sizeof(LEnt) * num_of_entries)) == NULL)
		return NULL;

	/* Set parameters */
	llist->head = lent;
	_prev_lent = NULL;
	_lent = lent;
	for (i = 0; i < num_of_entries; i++) {
		_lent->data = NULL;
		_lent->prev = _prev_lent;
		_prev_lent = _lent;
		_lent++;
		_prev_lent->next = _lent;
	}
	_prev_lent->next = NULL;
	llist->tail = _prev_lent;
	llist->last = NULL;

	return llist;
}

/* Add an entry to the beginning of a linked list */
LEnt *
LListPrepend(LList *llist, void *data)
{
	LEnt	*last_ent, *lent;

	/* Check first empty entry */
	if ((last_ent = llist->last) == NULL)
		lent = llist->head;
	else if ((lent = last_ent->next) == NULL)
		return NULL;
	else {
		lent->prev->next = lent->next;
		lent->prev = NULL;
		lent->next = llist->head;
	}

	/* Set parameters */
	lent->data = data;
	llist->head = lent;

	return lent;
}

/* Add an entry to the end of a linked list */
LEnt *
LListAppend(LList *llist, void *data)
{
	LEnt	*last_ent, *lent;

	/* Check last entry */
	last_ent = llist->last;
	lent = (last_ent == NULL) ?  llist->head : last_ent->next;

	if (lent != NULL) {
		lent->data = data;
		llist->last = lent;
	}

	return lent;
}
#endif

/*****************************************************************************
	Network 
*****************************************************************************/

/* Send all */
ssize_t
SendAll(int sock, const void *msg, int size, int flags)
{
	ssize_t	sent_size = 0, ret;
	char	*_msg = (char *)msg;

	do {
		if ((ret = send(sock, _msg + sent_size, size - sent_size,
				flags)) < 0)
			return -1;

		sent_size += ret;
	} while (sent_size < size);

	return sent_size;
}

/* Recv all */
ssize_t
RecvAll(int sock, void *msg, int size, int flags)
{
	ssize_t	recv_size = 0, ret;
	char	*_msg = (char *)msg;

	do {
		if ((ret = recv(sock, _msg + recv_size, size - recv_size,
				flags)) <= 0) {
			if (ret == 0) { // Disconnected
				errno = ECONNRESET;
			}
			return ret;
		}

		recv_size += ret;
	} while (recv_size < size);

	return recv_size;
}

#if 0
/* Receive with timeout -- kqueue version
   Returned values:
	-2: Error
	-1: recv() returned 0, ie, socket was closed
	 0: Timeout at select()
	Else: returned value of recv() */
ssize_t
RecvTimeout(int sock, void *data, size_t len, int tmout_msec)
{
	int		kq, ret;
	ssize_t		rret;
	struct kevent	kev;
	div_t		d;
	struct timespec	ts;

	/* Set timeout */
	d = div(tmout_msec, 1000);
	ts.tv_sec = d.quot;
	ts.tv_nsec = d.rem * 1000000;

	/* Initialize */
	if ((kq = kqueue()) < 0) {
		Log("Error: %s: kqueue: %s", __func__, strerror(errno));
		exit(1);
	}

	/* Add sock to kq */
	EV_SET(&kev, sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) < 0) {
		Log("Error: %s: kevent: %s", __func__, strerror(errno));
		exit(1);
	}

	/* Poll */
	ret = kevent(kq, NULL, 0, &kev, 1, &ts);
	if (ret < 0) { /* Error */
		Log("Error: %s: kevent: %s", __func__, strerror(errno));
		close(kq);
		return -2;
	}
	else if (ret == 0) { /* Timeout */
		close(kq);
		return 0;
	}

	if (kev.ident != sock) {
		Log("Error: %s: kevent: kev.ident [%d] != sock [%d]",
			__func__, kev.ident, sock);
		exit(1);
	}

	EV_SET(&kev, sock, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	kevent(kq, &kev, 1, NULL, 0, NULL);
	close(kq);

	/* Recieve data */
	rret = RecvAll(sock, data, len, 0);
	if (ret < 0) { /* Error */
		Log("Error: %s: recv: %s", __func__, strerror(errno));
		return -2;
	}
	else if (ret == 0) // Closed
		return -1;
	else
		return rret;
}
#else
/* Receive with timeout -- select() version
   Returned values:
	-2: Error with select() or recv()
	-1: recv() returned 0, ie, socket was closed
	 0: Timeout at select()
	Else: returned value of recv() */
ssize_t
RecvTimeout(int sock, void *data, size_t len, int tmout_msec)
{
	int		ret;
	ssize_t		_ret;
	div_t		d;
	struct timeval	tv;
	fd_set		fdset;

	/* Set timeout */
	if (tmout_msec) {
		d = div(tmout_msec, 1000);
		tv.tv_sec = d.quot;
		tv.tv_usec = d.rem * 1000;
	}

	/* Set socket */
	FD_ZERO(&fdset);
	FD_SET(sock, &fdset);

	/* Select */
	ret = select(sock + 1, &fdset, NULL, NULL, tmout_msec ? &tv : NULL);
	if (ret < 0) { /* Error */
		//Log("Error: %s: select: %s", __func__, strerror(errno));
		return -2;
	}
	else if (ret == 0) { /* Timeout */
		errno = ETIMEDOUT;
		return 0;
	}

	/* Recieve data */
	_ret = RecvAll(sock, data, len, 0);
	if (_ret < 0) { /* Error */
		//Log("Error: %s: RecvAll: %s", __func__, strerror(errno));
		return -2;
	}
	else if (_ret == 0) // Closed
		return -1;
	else
		return _ret;
}
#endif

// Set sock TCP_NODELAY, IPTOS_LOWDELAY, IPTOS_THROUGHPUT
int
SockSetTcpNoDelay(int sock, bool on)
{
	int	sockopt = (int)on;

	// Set TCP_NODELAY
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(int))
			< 0) {
		Log("Warning: %s: setsockopt TCP_NODELAY: %s",
			__func__, strerror(errno));
		return -1;
	}

#if 0	// IPv6 does not support these
	// IPTOS_LOWDELAY
	sockopt = IPTOS_LOWDELAY;
	if (setsockopt(sock, IPPROTO_IP, IP_TOS, &sockopt, sizeof(int)) < 0) {
		Log("Warning: %s: setsockopt IPTOS_LOWDELAY: %s",
			__func__, strerror(errno));
		return -1;
	}

	// IPTOS_THROUGHPUT
	sockopt = IPTOS_THROUGHPUT;
	if (setsockopt(sock, IPPROTO_IP, IP_TOS, &sockopt, sizeof(int)) < 0) {
		Log("Warning: %s: setsockopt IPTOS_THROUGHPUT: %s",
			__func__, strerror(errno));
		return -1;
	}
#endif

	return 0;
}

#ifdef _WIN32 // For non-Win, the following functions are defined in util.h
/* Winsock's send */
int
MySend(SOCKET fd, void *msg, int size, int flags)
{
	int	ret;
	int	_errno = 0;

	WSASetLastError(0);

	/* Send */
	if ((ret = SendAll(fd, msg, size, flags)) < 0) {
		_errno = WSAGetLastError();
		Log("Error: %s: send: %s", __func__, SockErrorMessage(_errno));
		WSASetLastError(_errno);
	}

	return ret;
}

/* Winsock's recv to handle WSAEWOULDBLOCK error */
int
MyRecv(SOCKET fd, void *msg, int size, int flags)
{
	int	ret;
	int	_errno = 0;

	WSASetLastError(0);

	/* Try to receive */
	if ((ret = recv(fd, msg, size, flags)) < 0)
		_errno = WSAGetLastError();

	/* If error is WSAEWOULDBLOCK, then wait until socket gets ready */
	if (_errno == WSAEWOULDBLOCK) {
		fd_set	rset;

		/* Initialize */
		FD_ZERO(&rset);

		/* Set server fd */
		FD_SET(fd, &rset);

		/* We have to select...... */
		if (select(0, &rset, NULL, NULL, NULL) < 0) {
			Log("Error: %s: select: %s",
				__func__, SockErrorMessage(0));
			return -1;
		}

		if (!FD_ISSET(fd, &rset)) {
			Log("Error: %s: select: fd not set. Impossible!!",
				__func__);
			return -1;
		}

		/* Receive */
		if ((ret = recv(fd, msg, size, flags)) < 0)
			Log("Error: %s: recv: %s",
				__func__, SockErrorMessage(0));

		WSASetLastError(0);
	}
	else if (_errno) {
		Log("Error: %s: recv: %s", __func__, SockErrorMessage(_errno));
		WSASetLastError(_errno);
	}

	return ret;
}
#endif //_WIN32

/* Receive unnecessary message */
int
RecvUnnecessaryMsg(int sock, size_t len)
{
	char	buf[BUFSIZ];
	int	ret;

	/* Receive message */
	do {
		ret = RecvAll(sock, buf,
			   (len > sizeof(buf)) ? sizeof(buf) : len, 0);
		if (ret <= 0)
			return ret;

		len -= ret;
	} while (len > 0);

	return ret;
}

/* Set socket non-blocking mode */
void
SockSetNonBlock(SOCKET fd)
{
#ifdef _WIN32 // For Win
	unsigned long	mode = 1;

	ioctlsocket(fd, FIONBIO, &mode);
#else // For Unix
	fcntl(fd, F_SETFL, O_NONBLOCK);
#endif //_WIN32
}

// Change send recv buf size
void
SetSndRcvBufSiz(int sock, int bufsiz)
{
	// Set socket option with new buf size
	if ((setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsiz, sizeof(int)))) {
		Log("Warning: %s: setsockopt SO_SNDBUF: %s",
			__func__, strerror(errno));
	}
	if ((setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsiz, sizeof(int)))) {
		Log("Warning: %s: setsockopt SO_RCVBUF: %s",
			__func__, strerror(errno));
	}
}

// Change send buf size
void
SetSndBufSiz(int sock, int bufsiz)
{
	// Set socket option with new buf size
	if ((setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsiz, sizeof(int)))) {
		Log("Warning: %s: setsockopt SO_SNDBUF: %s",
			__func__, strerror(errno));
	}
}

// Change recv buf size
void
SetRcvBufSiz(int sock, int bufsiz)
{
	// Set socket option with new buf size
	if ((setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsiz,
		sizeof(int)))) {
		Log("Warning: %s: setsockopt SO_RCVBUF: %s",
			__func__, strerror(errno));
	}
}


/*****************************************************************************
	Pipe 
*****************************************************************************/

/* Pipe -- send */
int
MyPipeSend(SOCKET fd, void *msg, int len)
{
#ifdef _WIN32 // For Win
	return MySend(fd, msg, len, 0);
#else // For Unix
	return write(fd, msg, len);
#endif // _WIN32
}

/* Pipe -- recv */
int
MyPipeRecv(SOCKET fd, void *msg, int len)
{
#ifdef _WIN32 // Win
	return MyRecv(fd, msg, len, 0);
#else // Unix
	return read(fd, msg, len);
#endif // _WIN32
}

#ifdef _WIN32 // MyPipe() and its associated functions are defined here only for Windows. For other OSs like *nix, MyPipe() = pipe().

static unsigned short	pipe_port = 61938;

/* MyPipe's client thread */
static int
MyPipeClient(void *data)
{
	SOCKET 			*fd = (SOCKET *) data;
	struct sockaddr_in	addr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(pipe_port);

	/* Open socket for sending */
	if ((fd[1] = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		Log("Error: %s: socket: fd[1]: %s",
			__func__, SockErrorMessage(0));
		return -1;
	}
 
	/* Connect */
	if (connect(fd[1], (struct sockaddr *) &addr, sizeof(addr))) {
		Log("Error: %s: connect: fd[1]: %s",
			__func__, SockErrorMessage(0));
		return -1;
	}

	return 0;
}

/* Pipe -- I know this is a stinky impelementation... But Windows.... */
int
MyPipe(SOCKET fd[])
{
	SOCKET			sock_accpt;
	struct sockaddr_in	addr, cli_addr;
	int			cli_addr_size = (int) sizeof(cli_addr);
	pthread_t		pt_id;
	unsigned long		mode = 0;

	pipe_port++;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	/* Open socket for receiving */
	if ((sock_accpt = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		Log("Error: %s: socket: sock_accpt: %s",
			__func__, strerror(errno));
		return -1;
	}

	/* Find unused port */
	for (; pipe_port < 65535; pipe_port++) {
		addr.sin_port = htons(pipe_port);

		/* Bind */
		if (bind(sock_accpt, (struct sockaddr *) &addr,
			 sizeof(struct sockaddr_in)) == 0)
			break;
	}
	if (pipe_port == 65535) {
		Log("%s: bind: no open port found.", __func__);
		return -1;
	}

	/* Listen */
	listen(sock_accpt, 1);

	/* Create thread for sending */
	if (pthread_create(&pt_id, NULL, (void *(*)(void*)) MyPipeClient, fd)) {
		Log("Error: %s: pthread_create: %s", __func__, strerror(errno));
		return -1;
	}

	/* Accept */
	fd[0] = accept(sock_accpt, (struct sockaddr *) &cli_addr,
		       &cli_addr_size);

	/* Wait for client */
	pthread_join(pt_id, NULL);

	/* Set blocking mode */
	ioctlsocket(fd[0], FIONBIO, &mode);
	ioctlsocket(fd[1], FIONBIO, &mode);

	//MyMessage("pthread_join OK\n");

	return 0;
}

#endif // _WIN32

/* Open pipes for communication between threads */
int
ThreadPipes(SOCKET fd[][2])
{
	int	i;

	for (i = 0; i < PIPE_NUM; i++) {
		if (MyPipe(fd[i]) < 0)
			return -1;
	}

	return 0;
}

/* Close thread pipes */
void
ThreadPipesClose(SOCKET fd[][2])
{
	int	i, _fd;

	for (i = 0; i < PIPE_NUM; i++) {
		if ((_fd = fd[i][0]) > 0) {
			closesocket(_fd);
		}
		if ((_fd = fd[i][1]) > 0) {
			closesocket(_fd);
		}
	}

}

/*****************************************************************************
	String list
*****************************************************************************/

#if 1
// Search string in string list
char *
StrListSearch(StrList *sl, const char *str)
{
	char	*p, *end, c;

	if (sl->list == NULL) {
		return NULL;
	}

	p = sl->list;
	end = p + sl->len;
	while (p < end) {
		c = *p;
		if (c == '\0') {
			p++;
			continue;
		}
		else if (c != *str) {
			p = EndOfStr(p, end - p) + 1;
			continue;
		}
		else if (strcmp(p + 1, str + 1) == 0) { // Found
			return p;
		}
		else {
			p = EndOfStr(p, end - p) + 1;
		}
	}

	// Not found
	return NULL;
}
#else
// Search string in string list
char *
StrListSearch(StrList *sl, char *str)
{
	char	*p;
	size_t	s, len = sl->len;

	if (sl->list == NULL) {
		return NULL;
	}

	p = sl->list;
	for (s = 0; s < len; ) {
		if (strcmp(p, str) == 0) { // Found
			return p;
		}
		p = EndOfStr(p, len - s) + 1;
		s = p - sl->list;
	}

	// Not found
	return NULL;
}
#endif

// Append string to string list
int
StrListAppend(StrList *sl, const char *str)
{
	char	*llist, *p;
	size_t	max_size, curr_pos;

	// Check list
	if (sl->list == NULL || sl->size == 0) { // Create new list
		max_size = 16384;
		if ((llist = (char *)malloc(max_size)) == NULL) {
			sl->list = NULL;
			sl->size = sl->len = 0;
			return -1;
		}
		else {
			sl->list = llist;
			sl->size = 16384;
			sl->len = 0;
		}
	}
	else if (sl->len + PATH_MAX + 2 > sl->size) { // Check size of list
		// Reallocate list
		max_size = sl->size + 16384;
		if ((llist = (char *)realloc(sl->list, max_size)) == NULL) {
			return -1;
		}
		else {
			sl->list = llist;
			sl->size = max_size;
		}
	}

	// Append str
	llist = sl->list;
	curr_pos = sl->len;
	p = stpcpy(&llist[curr_pos], str) + 1;
	sl->len = p - llist;

	return 0;
}

// Append StrList to StrList (with possible duplication)
int
StrListAppendList(StrList *sl1, StrList *sl2)
{
	char	*p = sl2->list, *end = p + sl2->len;

	if (p == NULL) {
		return 0;
	}

	while (p < end) {
		// Skip '\0'
		if (*p == '\0') {
			p++;
			continue;
		}

		// Append
		if (StrListAppend(sl1, p) < 0) {
			return -1;
		}
		p = EndOfStr(p, end - p) + 1;
	}

	// End
	return 0;
}

// Remove duplication and merge sl1 and sl2, then store result in sl1
int
StrListMerge(StrList *sl1, StrList *sl2)
{
	char	*p = sl2->list, *end = p + sl2->len;

	if (p == NULL) {
		return 0;
	}

	while (p < end) {
		// Skip '\0'
		if (*p == '\0') {
			p++;
			continue;
		}

		// Search p in sl1
		if (StrListSearch(sl1, p) == NULL) { // p not registered in sl1
			// Append
			if (StrListAppend(sl1, p) < 0) {
				return -1;
			}
		}
		p = EndOfStr(p, end - p) + 1;
	}

	// End
	return 0;
}

// Count # of items in list
int64_t
StrListCount(StrList *sl)
{
	char	*p = sl->list, *end = p + sl->len;
	int64_t	count = 0;

	if (p == NULL) {
		return 0;
	}

	while (p < end) {
		if (*p == '\0') {
			p++;
			continue;
		}
		count++;
		p = EndOfStr(p, end - p) + 1;
	}

	return count;
}

// Show strings in list
void
StrListShow(StrList *sl)
{
	char	*p = sl->list, *end = p + sl->len;

	if (p == NULL) {
		return;
	}

	while (p < end) {
		if (*p == '\0') {
			p++;
			continue;
		}

		puts(p);
		//printf("%p: %s\n", p, p);
		p = EndOfStr(p, end - p) + 1;
	}
}

// Free StrList
void
StrListFree(StrList *sl)
{
	char	*p = sl->list;

	if (p != NULL) {
		free(p);
	}
}

/* Return hash code between 0 and 2^bits - 1 -- bits must be <= 32 */
int32_t
MyHash(const char *str, int bits)
{
	unsigned char	*p, c;
	uint32_t	ret = 0;
	
	for (p = (unsigned char *)str;; p++) {
		if ((c = *p) == 0)
			break;

		ret += (uint32_t)c;
	}

	return ret & ((1 << bits) - 1);
}


/*****************************************************************************
	Modified MaPrime2C Hash
*****************************************************************************/

#define PRIME_MULT 1717

static const unsigned char maPrime2CTable[256] =
    {
      0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
      0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
      0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
      0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
      0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
      0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
      0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
      0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
      0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
      0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
      0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
      0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
      0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
      0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
      0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
      0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46
    };

// Good 32bit hash? (based on MaPrime2cHash)
uint32_t
MyPrime2cHash(const char *str, unsigned int len)
{
	unsigned char	*p = (unsigned char *)str;
	uint32_t	hash = 0, i;

	for (i = 0; i != len; i++, p++) {
		hash += *p;
	}

	for (i = 0, p = (unsigned char *)str; i != len; i++, p++) {
		hash ^= maPrime2CTable[(*p + i) & 255];
		hash *= PRIME_MULT;
	}

	return hash;
}

// 64bit hash based on siphash24
uint64_t
MyHash64(const char *str, size_t len)
{
	const char	key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 
				   0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

	return siphash24(str, len, key);
}

// Show hash
void
ShowHash(uint8_t *hash, size_t size)
{
	size_t	i;

	for (i = 0; i < size; i++) {
		printf("%02x", hash[i]);
	}
	putchar('\n');
}

#if 1
// Copy file using sendfile
int
CopyFile(const char *src, const char *dst)
{
	char	buf[BUFSIZ], *p;
	int	fdS = -1, fdD = -1, err = 0;
	ssize_t	rsiz, wsiz;

	// Open files
	if ((fdS = open(src, O_RDONLY)) < 0) {
		err = errno;
		goto END;
	}
	if ((fdD = open(dst, O_WRONLY | O_CREAT, 0666)) < 0) {
		err = errno;
		goto END;
	}

	// Copy
	while ((rsiz = read(fdS, buf, sizeof(buf))) > 0) {
		p = buf;
		do {
			wsiz = write(fdD, p, rsiz);
			if (wsiz > 0) {
				rsiz -= wsiz;
				p += wsiz;
			}
			else if (wsiz < 0 && errno != EINTR) {
				err = errno;
				goto END;
			}
		} while (rsiz > 0);
	}
	if (rsiz < 0) { // Error;
		err = errno;
		goto END;
	}

END:	// Finalize
	if (fdS >= 0) {
		close(fdS);
	}
	if (fdD >= 0) {
		close(fdD);
	}

	return err ? -1 : 0;
}
#else // Using sendfile does not work with FreeBSD
// Copy file using sendfile
int
CopyFile(const char *src, const char *dst)
{
	int	fdS = -1, fdD = -1, err = 0;
	off_t	csize;

	// Open files
	if ((fdS = open(src, O_RDONLY)) < 0) {
		err = errno;
		goto END;
	}
	if ((fdD = open(src, O_WRONLY | O_CREAT, 0666)) < 0) {
		err = errno;
		goto END;
	}

	// Copy
	if (sendfile(fdS, fdD, 0, 0, NULL, &csize, 0) < 0) { // Error
		err = errno;
		goto END;
	}

END:	// Finalize
	if (fdS >= 0) {
		close(fdS);
	}
	if (fdD >= 0) {
		close(fdD);
	}

	return err ? -1 : 0;
}
#endif

/*****************************************************************************
	Replacement of FreeBSD's thread-unsafe dirname 
	It overwrites the input path
*****************************************************************************/

char *
Dirname(char *path)
{
	char	*p = strrchr(path, '/');

	if (p == NULL) {
		path[0] = '.';
		path[1] = '\0';
	}
	else if (p == path) { // '/' root dir
		p[1] = '\0';
	} 
	else {
		*p = '\0';
	}
	return path;
}

/*****************************************************************************
	Recursive functions 
*****************************************************************************/

int
RecursiveMkdir(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	char		buf[PATH_MAX], *p, *_p;
	struct stat	sb;

	errno = 0;
	strncpy(buf, path, sizeof(buf) - 1);
	_p = p = (buf[0] == '/') ? buf + 1 : buf;
	while ((p = strchr(p, '/')) != NULL) {
		*p = '\0';

		// Check dir
		//if (lstat(buf, &sb) < 0) { // Dir does not exist
		if (stat(buf, &sb) < 0) { // Dir does not exist
			// Mkdir
			if (mkdir(buf, mode) < 0 && errno != EEXIST) { // Err
				Log("Error: %s: mkdir %s: %s",
					__func__, buf, strerror(errno));
				return -1;
			}

			// Chmod  
			if (chmod(buf, mode) < 0) {
				Log("Warning: %s: chmod %s: %s",
					__func__, buf, strerror(errno));
			}

			// Chown
			if (chown(buf, uid, gid) < 0) {
				Log("Warning: %s: chown %s: %s",
					__func__, buf, strerror(errno));
			}

			// Check errno
			if (errno == ENOENT) {
				errno = 0; // Ignore err
			}
		}
		else if (!S_ISDIR(sb.st_mode)) { // Not directory
			Log("Error: %s: %s is not a directory", __func__, buf);
			errno = EPERM;
			return -1;
		}

		*p = '/';
		p++;
		_p = p;
	}

	// Mkdir last dir
	if (*_p != '\0') {
		if (mkdir(buf, mode) < 0 && errno != EEXIST) { // Error
			Log("Error: %s: mkdir %s: %s",
				__func__, buf, strerror(errno));
			return -1;
		}
		else {
			// Reset error for EEXIST
			errno = 0;

			// Chmod  
			if (chmod(buf, mode) < 0) {
				Log("Warning: %s: chmod %s: %s",
					__func__, buf, strerror(errno));
			}

			// Chown
			if (chown(buf, uid, gid) < 0) {
				Log("Warning: %s: chown %s: %s",
					__func__, buf, strerror(errno));
			}

			return errno ? -1 : 0;
		}
	}
	else {
		return 0;
	}
}

// Check dir for the given path. If dir does not exist, then create it
int
CheckDir(const char *path)
{
	char		ppath[PATH_MAX], *dir;
	int		err = 0;
	struct stat	sb;

	// Copy path
	strncpy(ppath, path, sizeof(ppath) - 1);

	// Check dir
	if ((dir = Dirname(ppath)) != NULL) {
		if (lstat(dir, &sb) < 0) { // Dir does not exist
			// Recursively mkdir
#if 1
			if (RecursiveMkdir(dir, 0777, -1, -1) < 0) {
#else
			if (RecursiveMkdir(dir,
				S_IRUSR | S_IWUSR | S_IXUSR |
				S_IRGRP | S_IWGRP | S_IXGRP |
				S_IROTH | S_IWOTH | S_IXOTH) < 0) {
#endif
				Log("Error: %s: RecursiveMkdir %s: %s",
					__func__, dir, strerror(errno));
				err = errno;
			}
		}
	}

	return err ? -1 : 0;
}

// Recursively remove files and directories: note 'dir' can be a file
int
RecursiveRm(const char *dir)
{
	int	err = 0;
	FTS	*ftsp = NULL;
	FTSENT	*curr;

	// Cast needed because fts_open() takes a "char * const *", instead
	// of a "const char * const *", which is only allowed in C++. fts_open()
	// does not modify the argument.
	char *files[] = {(char *)dir, NULL};

	// FTS_NOCHDIR  - Avoid changing cwd, which could cause unexpected 
	//                behavior in multithreaded programs
	// FTS_PHYSICAL - Don't follow symlinks. Prevents deletion of files
	//                outside of the specified directory
	// FTS_XDEV     - Don't cross filesystem boundaries
	ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
	if (!ftsp) {
		Log("Error: %s: %s: fts_open: %s",
			__func__, dir, strerror(errno));
		err = errno;
		goto END;
	}

	while ((curr = fts_read(ftsp))) {
		switch (curr->fts_info) {
		case FTS_NS:
		case FTS_DNR:
		case FTS_ERR:
			err = curr->fts_errno;
			if (err != ENOENT) {
				Log("Error: %s: %s: fts_read: %s", __func__,
					curr->fts_accpath, strerror(err));
			}
			break;

		case FTS_DC:
		case FTS_DOT:
		case FTS_NSOK:
			// Not reached unless FTS_LOGICAL, FTS_SEEDOT,
			// or FTS_NOSTAT were  passed to fts_open()
			break;

		case FTS_D:
			// Do nothing. Need depth-first search, so
			// directories are deleted in FTS_DP
			break;

		case FTS_DP:
		case FTS_F:
		case FTS_SL:
		case FTS_SLNONE:
		case FTS_DEFAULT:
			if (remove(curr->fts_accpath) < 0 && errno != ENOENT) {
				Log("Error: %s: %s: Failed to remove: %s",
					__func__, curr->fts_accpath,
					strerror(errno));
				err = errno;
			}
			break;
		}
	}

END:	// Finalize
	if (ftsp) {
		fts_close(ftsp);
	}

	if (err) {
		errno = err;
		return -1;
	}
	else {
		return 0;
	}
}

// Recursively remove files and directories while checking sock
// This cancels removing when sock receives message
int
RecursRmCheckSock(const char *dir, int sock)
{
	int		err = 0;
	FTS		*ftsp = NULL;
	FTSENT		*curr;
	fd_set		fdset;
	struct timeval	tv = {0, 0};

	// Initialize for sock
	FD_ZERO(&fdset);
	FD_SET(sock, &fdset);

	// Cast needed because fts_open() takes a "char * const *", instead
	// of a "const char * const *", which is only allowed in C++. fts_open()
	// does not modify the argument.
	char *files[] = {(char *)dir, NULL};

	// FTS_NOCHDIR  - Avoid changing cwd, which could cause unexpected 
	//                behavior in multithreaded programs
	// FTS_PHYSICAL - Don't follow symlinks. Prevents deletion of files
	//                outside of the specified directory
	// FTS_XDEV     - Don't cross filesystem boundaries
	ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
	if (!ftsp) {
		if (errno != ENOENT) {
			Log("Error: %s: %s: fts_open: %s",
				__func__, dir, strerror(errno));
		}
		err = errno;
		goto END;
	}

	while ((curr = fts_read(ftsp))) {
		// Check sock -- Cancel removing if sock has message
		if (select(sock + 1, &fdset, NULL, NULL, &tv) > 0) {
			Log("Info: %s: Received socket event", __func__);
			err = ECANCELED;
			break;
		}

		// Check entry's info
		switch (curr->fts_info) {
		case FTS_NS:
		case FTS_DNR:
		case FTS_ERR:
			err = curr->fts_errno;
			Log("Error: %s: %s: fts_read: %s",
				__func__, curr->fts_accpath, strerror(err));
			break;

		case FTS_DC:
		case FTS_DOT:
		case FTS_NSOK:
			// Not reached unless FTS_LOGICAL, FTS_SEEDOT,
			// or FTS_NOSTAT were  passed to fts_open()
			break;

		case FTS_D:
			// Do nothing. Need depth-first search, so
			// directories are deleted in FTS_DP
			break;

		case FTS_DP:
		case FTS_F:
		case FTS_SL:
		case FTS_SLNONE:
		case FTS_DEFAULT:
			if (remove(curr->fts_accpath) < 0 && errno != ENOENT) {
				Log("Error: %s: %s: Failed to remove: %s",
					__func__, curr->fts_accpath,
					strerror(errno));
				err = errno;
			}
			break;
		}
	}

END:	// Finalize
	if (ftsp) {
		fts_close(ftsp);
	}

	if (err) {
		errno = err;
		return -1;
	}
	else {
		return 0;
	}
}

// Get all entries under dir
StrList *
DirGetEntriesAll(const char *dir)
{
	int	err = 0;
	FTS	*ftsp = NULL;
	FTSENT	*curr;
	char	*files[] = {(char *)dir, NULL};
	StrList	*sl = NULL;

	// Open
	// FTS_NOCHDIR  - Avoid changing cwd, which could cause unexpected 
	//                behavior in multithreaded programs
	// FTS_PHYSICAL - Don't follow symlinks. Prevents deletion of files
	//                outside of the specified directory
	// FTS_XDEV     - Don't cross filesystem boundaries
	if ((ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV,
			NULL)) == NULL) {
		Log("Error: %s: %s: fts_open: %s",
			__func__, dir, strerror(errno));
		err = errno;
		goto END;
	}

	// Allocate sl
	if ((sl = (StrList *)malloc(sizeof(StrList))) == NULL) {
		Log("Error: %s: malloc sl: %s", __func__, strerror(errno));
		err = errno;
		goto END;
	}
	sl->list = NULL;
	sl->size = sl->len = 0;

	// Scan
	while ((curr = fts_read(ftsp))) {
		switch (curr->fts_info) {
		case FTS_NS:
		case FTS_DNR:
		case FTS_ERR:
			errno = err = curr->fts_errno;
			Log("Error: %s %s: fts_read error: %s",
				__func__, curr->fts_accpath, strerror(err));
			goto END;

		case FTS_DC:
		case FTS_DOT:
		case FTS_NSOK:
			// Not reached unless FTS_LOGICAL, FTS_SEEDOT,
			// or FTS_NOSTAT were  passed to fts_open()
			break;

		case FTS_D:
			// Do nothing. Need depth-first search, so
			// directories are deleted in FTS_DP
			break;

		case FTS_DP:
		case FTS_F:
		case FTS_SL:
		case FTS_SLNONE:
		case FTS_DEFAULT:
			// Append entry to list
			if (StrListAppend(sl, curr->fts_accpath) == -1) {
				Log("Error: %s %s: StrListAppend: %s",
					__func__, curr->fts_accpath,
					strerror(errno));
				err = errno;
				goto END;
			}
			break;
		}
	}

END:	// Finalize
	if (ftsp) {
		fts_close(ftsp);
	}
	if (err) {
		if (sl != NULL) {
			StrListFree(sl);
			free(sl);
		}
		return NULL;
	}
	else {
		return sl;
	}
}

/*****************************************************************************
	
*****************************************************************************/

// utimens for FreeBSD
int
Utimens(const char *path, const struct timespec *ts)
{
	if (ts == NULL) {
		return lutimes(path, NULL);
	}
	else {
		struct timeval	tv[2];

		TIMESPEC_TO_TIMEVAL(tv, ts);
		TIMESPEC_TO_TIMEVAL(tv + 1, ts + 1);

		return lutimes(path, tv);
	}
}

// futimens for FreeBSD
int
Futimens(int fd, const struct timespec *ts)
{
	if (ts == NULL) {
		return futimes(fd, NULL);
	}
	else {
		struct timeval	tv[2];

		TIMESPEC_TO_TIMEVAL(tv, ts);
		TIMESPEC_TO_TIMEVAL(tv + 1, ts + 1);

		return futimes(fd, tv);
	}
}

// Read dir and store in StrList
StrList *
DirStrList(const char *dir)
{
	char		path[PATH_MAX], *name;
	int		err = 0;
	DIR		*dp = NULL;
	struct dirent	*de;
	StrList		*naml = NULL;

	// Allocate and initialize naml
	if ((naml = (StrList *)malloc(sizeof(StrList))) == NULL) {
		Log("Error: %s: malloc naml: %s", __func__, strerror(errno));
		err = errno;
		goto END;
	}
	naml->list = NULL;
	naml->size = 0;
	naml->len = 0;

	// Open dir
	if ((dp = opendir(dir)) == NULL) {
		Log("Error: %s: opendir %s: %s",
			__func__, path, strerror(errno));
		err = errno;
		goto END;
	}

	// Read dir
	while ((de = readdir(dp)) != NULL) {
		name = de->d_name;

		// Skip . and .. and .tmp*
		if (name[0] == '.') {
			switch (name[1]) {
			case '\0': // .
				continue;
			case '.':
				if (name[2] == '\0') { // ..
					continue;
				}
/*
				else if (strcmp(name + 2, HNCDIR_FILE + 2)
						== 0) {
					// HNCDIR_FILE
					continue;
				}
*/
				else {
					break;
				}
			default:
#ifdef __FreeBSD__
				if (strcmp(name + 1, "snap") == 0) {
					// .snap
					continue;
				}
				else if (strcmp(name + 1, "sujournal") == 0) {
					// .sujournal
						continue;
				}
#endif
				break;
			}
		}
		//DebugMsg("%s: %s\n", path, name);

		// Append name
		if (StrListAppend(naml, name) < 0) {
			Log("Error: %s: StrListAppend: %s",
				__func__, strerror(errno));
			err = errno;
			goto END;
		}
	}

/*
	if (Debug && naml->list != NULL) {
		DebugMsg("naml:\n");
		StrListShow(naml);
	}
*/


END:
	// Finalize
	if (dp != NULL) {
		closedir(dp);
	}
	if (err) {
		errno = err;
		if (naml != NULL) {
			StrListFree(naml);
			free(naml);
		}
		return NULL;
	}
	else {
		return naml;
	}
}

// Get program name from argv[0]
void
GetProgramName(const char *argv_0, char *program, size_t size)
{
	char	*p;

	if ((p = strrchr(argv_0, '/')) != NULL) {
		p++;
	}
	else {
		p = (char *)argv_0;
	}
	strncpy(program, p, size - 1);
}

// Exec program by automatically checking PATH env
int
ExecAutoPath(const char *prog, char *const argv[]) 
{
	char	*str, *p, buf[BUFSIZ], path[PATH_MAX];

	// Get PATH env
	if ((str = getenv("PATH")) == NULL) { // Failed
#if 1
		str = "/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:"
		      "/usr/local/bin";
#else
		Log("Error: %s: getenv PATH: Not found", __func__);
		errno = EPERM;
		return -1;
#endif
	}

	// Try each path
	strncpy(buf, str, sizeof(buf));
	for (p = buf;;) {
		// Get path
		if ((p = strtok(p, ":")) == NULL) {
			break;
		}

		// Create new prog path 
		snprintf(path, sizeof(path), "%s/%s", p, prog);

		// Exec
		execv(path, argv);
		p = NULL;
	}

	errno = ENOENT; // This is not necessary though
	return -1;
}

// Restart with given program and args
// We assume argv[argc] = NULL
void
RestartProgram(const char *prog, char *const argv[])
{
	switch (fork()) {
	case -1: // Error
		Log("Error: %s: fork: %s", __func__, strerror(errno));
		return;
	
	case 0: // New process
		sleep(3); // Sleep 3 sec
		execv(prog, argv);

	default: // This process, exit
		exit(0);
	}
}

/*****************************************************************************
	Memory allocation test
*****************************************************************************/

#ifdef malloc
#undef malloc
// For memory allocation test
void *
Malloc(size_t size)
{
	void	*m;

	m = malloc(size);
	//printf("\033[1mAllocated: %p, %lu bytes\033[0m\n", m, size);
	printf("Allocated: %p, %lu bytes\n", m, size);

	return m;
}
#endif

#ifdef free
#undef free
// Free
void
Free(void *p)
{
	free(p);
	//printf("\033[1mFreed: %p\033[0m\n", p);
	printf("Freed: %p\n", p);
}
#endif

/*****************************************************************************
	Read/write lock for pthread
*****************************************************************************/

// Initialize PtLock
int
PtLockInit(PtLock *ptl)
{
	int	ret;

	// Initialize ptl
	ptl->numR = 0;
	ptl->numW = 0;
	ptl->numWW = 0;
	if ((ret = pthread_mutex_init(&ptl->mutex, NULL))) {
                Log("Error: %s: pthread_mutex_init: %s",
                        __func__, strerror(ret));
		errno = ret;
		return -1;
        }
	if ((ret = pthread_cond_init(&ptl->condR, NULL))) {
                Log("Error: %s: pthread_cond_init condR: %s",
                        __func__, strerror(ret));
		pthread_mutex_destroy(&ptl->mutex);
		errno = ret;
		return -1;
        }
	if ((ret = pthread_cond_init(&ptl->condW, NULL))) {
                Log("Error: %s: pthread_cond_init condR: %s",
                        __func__, strerror(ret));
		pthread_mutex_destroy(&ptl->mutex);
		pthread_cond_destroy(&ptl->condR);
		errno = ret;
		return -1;
        }

	return 0;
}

// Destroy PtLock
void
PtLockDestroy(PtLock *ptl)
{
	pthread_mutex_destroy(&ptl->mutex);
	pthread_cond_destroy(&ptl->condR);
	pthread_cond_destroy(&ptl->condW);
}

// Lock read
int
PtLockLockR(PtLock *ptl)
{
	int	ret;

	// Lock mutex anyway
	if ((ret = pthread_mutex_lock(&ptl->mutex))) {
                Log("Error: %s: pthread_mutex_lock: %s",
                        __func__, strerror(ret));
		errno = ret;
		return -1;
        }

	// Wait until there is no writer
	while (ptl->numW > 0 || ptl->numWW > 0) {
//printf("numW = %d, numWW = %d\n", ptl->numW, ptl->numWW);
		if ((ret = pthread_cond_wait(&ptl->condR, &ptl->mutex))) {
                	Log("Error: %s: pthread_cond_wait: %s",
                        	__func__, strerror(ret));
			errno = ret;
			return -1;
		}
	}
	ptl->numR++;

	// Unlock
	if ((ret = pthread_mutex_unlock(&ptl->mutex))) {
                Log("Error: %s: pthread_mutex_unlock: %s",
                        __func__, strerror(ret));
		errno = ret;
		return -1;
        }

	return 0;
}

// Unlock read
int
PtLockUnlockR(PtLock *ptl)
{
	int	ret;

	// Lock mutex anyway
	if ((ret = pthread_mutex_lock(&ptl->mutex))) {
                Log("Error: %s: pthread_mutex_lock: %s",
                        __func__, strerror(ret));
		errno = ret;
		return -1;
        }

	// Decrement # of readers
	ptl->numR--;

	// Signal to other threads if no readers and a waiting writers
	if (ptl->numR == 0 && ptl->numWW > 0) {
		if ((ret = pthread_cond_signal(&ptl->condW))) {
                	Log("Error: %s: pthread_cond_signal: %s",
                        	__func__, strerror(ret));
			errno = ret;
			return -1;
		}
	}

	// Unlock
	if ((ret = pthread_mutex_unlock(&ptl->mutex))) {
                Log("Error: %s: pthread_mutex_unlock: %s",
                        __func__, strerror(ret));
		errno = ret;
		return -1;
        }

	return 0;
}

// Lock write
int
PtLockLockW(PtLock *ptl)
{
	int	ret;

	// Lock mutex anyway
	if ((ret = pthread_mutex_lock(&ptl->mutex))) {
                Log("Error: %s: pthread_mutex_lock: %s",
                        __func__, strerror(ret));
		errno = ret;
		return -1;
        }

	// Increment # of waiting writers
	ptl->numWW++;

	// Wait until there are no readers and no writers
	while (ptl->numR > 0 || ptl->numW > 0) {
		if ((ret = pthread_cond_wait(&ptl->condW, &ptl->mutex))) {
                	Log("Error: %s: pthread_cond_wait: %s",
                        	__func__, strerror(ret));
			errno = ret;
			return -1;
		}
	}

	// Decrement # of writers
	ptl->numWW--;
	ptl->numW++;

	// Unlock
	if ((ret = pthread_mutex_unlock(&ptl->mutex))) {
                Log("Error: %s: pthread_mutex_unlock: %s",
                        __func__, strerror(ret));
		errno = ret;
		return -1;
        }

	return 0;
}

// Unlock write
int
PtLockUnlockW(PtLock *ptl)
{
	int	ret;

	// Lock mutex anyway
	if ((ret = pthread_mutex_lock(&ptl->mutex))) {
                Log("Error: %s: pthread_mutex_lock: %s",
                        __func__, strerror(ret));
		errno = ret;
		return -1;
        }

	// Decrement # of writers
	ptl->numW--;
//printf("%s: numW = %d, numWW = %d\n", __func__, ptl->numW, ptl->numWW);

	// Signal to other threads if no waiting writers
	if (ptl->numWW > 0) {
		if ((ret = pthread_cond_signal(&ptl->condW))) {
                	Log("Error: %s: pthread_cond_signal: %s",
                        	__func__, strerror(ret));
			errno = ret;
			return -1;
		}
	}
	// Signal to readers if no more waiting writers
	else if ((ret = pthread_cond_broadcast(&ptl->condR))) {
               	Log("Error: %s: pthread_cond_broadcast: %s",
                       	__func__, strerror(ret));
		errno = ret;
		return -1;
	}

	// Unlock
	if ((ret = pthread_mutex_unlock(&ptl->mutex))) {
                Log("Error: %s: pthread_mutex_unlock: %s",
                        __func__, strerror(ret));
		errno = ret;
		return -1;
        }

	return 0;
}

/*****************************************************************************
	Some useful functions for IPv4/v6
*****************************************************************************/

// Return IPv4 mapped address in IPv6 address
in_addr_t
V4MappedV6Addr(struct sockaddr_storage *addr)
{
	uint16_t	head[6] = {0, 0, 0, 0, 0, 0xffff};
	void		*addr6 = &((struct sockaddr_in6 *)addr)->sin6_addr;

	// Check v4 or v6
	switch (addr->ss_family) {
	case AF_INET:
		return ((struct sockaddr_in *)addr)->sin_addr.s_addr;

	case AF_INET6: // Check below
		// Check if addr is v4 mapped
		return (memcmp(addr6, head, 12) == 0) ?
			//ntohl(((uint32_t *)addr6)[3]) : 0; // Wrong
			((uint32_t *)addr6)[3] : 0;

	default:
		return 0;
	}
}

// Return IP address
void *
get_in_addr(struct sockaddr *sa)
{
	return (sa->sa_family == AF_INET) ?
		(void *)&(((struct sockaddr_in*)sa)->sin_addr) :
		(void *)&(((struct sockaddr_in6*)sa)->sin6_addr);

/*
	// Use like
	struct addrinfo	*p;
	char		s[INET6_ADDRSTRLEN];

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
		s, sizeof s);
*/
}

/*****************************************************************************
	File and memory
*****************************************************************************/

// Read entire file into memory and return it
int
ReadFile(const char *path, uint8_t **data, size_t *size)
{
	int		err = 0;
	uint8_t		*_data = NULL;
	FILE		*fp = NULL;
	size_t		_size = 0;
	struct stat	sb;

	// Open file
	if ((fp = fopen(path, "rb")) == NULL) {
		Log("Error: fopen %s: %s", path, strerror(errno));
		return -1;
	}

	// Get file size
	if (fstat(fileno(fp), &sb) == -1) {
		Log("Error: %s: fstat %s: %s", __func__, path, strerror(errno));
		err = errno;
		goto END;
	}
	_size = sb.st_size;

	// Allocate _data
	if ((_data = (uint8_t *)malloc(_size)) == NULL) {
		Log("Error: %s: malloc for %s: %s",
			__func__, path, strerror(errno));
		err = errno;
		goto END;
	}

	// Read
	if (fread(_data, 1, _size, fp) != _size) {
		if (feof(fp)) {
			Log("Error: %s: fread for %s: Reached EOF before "
			    "reading entire file", __func__, path);
		}
		else if (ferror(fp)) {
			Log("Error: %s: fread for %s: Failed to read",
				__func__, path);
		}
		else {
			Log("Error: %s: fread for %s: Unkown error",
				__func__, path);
		}
		errno = EPERM;
		goto END;
	}

END:	// Finalize
	if (fp != NULL) {
		fclose(fp);
	}

	if (err) {
		if (_data != NULL) {
			free(_data);
		}
		return -1;
	}
	else {
		*data = _data;
		*size = _size;

		return 0;
	}
}

// Write data to file
int
WriteFile(const char *path, const uint8_t *data, size_t size)
{
	int	err = 0;
	FILE	*fp = NULL;

	// Open file
	if ((fp = fopen(path, "wb")) == NULL) {
		Log("Error: fopen %s: %s", path, strerror(errno));
		return -1;
	}

	// Read
	if (fwrite(data, 1, size, fp) != size) {
		if (feof(fp)) {
			Log("Error: %s: fwrite for %s: Reached EOF before "
			    "writinf entire data", __func__, path);
		}
		else if (ferror(fp)) {
			Log("Error: %s: fwrite for %s: Failed to write",
				__func__, path);
		}
		else {
			Log("Error: %s: fwrite for %s: Unkown error",
				__func__, path);
		}
		errno = EPERM;
		goto END;
	}

END:	// Finalize
	if (fp != NULL) {
		fclose(fp);
	}

	return err ? -1 : 0;
}

#if defined(__linux__) || (__FreeBSD__ >= 12)
/*****************************************************************************
	For Linux
*****************************************************************************/

// Thread safe basename
char *
basename_r(const char *path, char *bname)
{
	const char *endp, *startp;
	size_t len;

	/* Empty or NULL string gets treated as "." */
	if (path == NULL || *path == '\0') {
		bname[0] = '.';
		bname[1] = '\0';
		return (bname);
	}

	/* Strip any trailing slashes */
	endp = path + strlen(path) - 1;
	while (endp > path && *endp == '/')
		endp--;

	/* All slashes becomes "/" */
	if (endp == path && *endp == '/') {
		bname[0] = '/';
		bname[1] = '\0';
		return (bname);
	}

	/* Find the start of the base */
	startp = endp;
	while (startp > path && *(startp - 1) != '/')
		startp--;

	len = endp - startp + 1;
	if (len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		return (NULL);
	}
	memcpy(bname, startp, len);
	bname[len] = '\0';
	return (bname);
}

/*
char *
basename(const char *path)
{
	static char *bname = NULL;

	if (bname == NULL) {
		bname = (char *)malloc(MAXPATHLEN);
		if (bname == NULL)
			return (NULL);
	}
	return (basename_r(path, bname));
}
*/
#endif

#if defined(__linux__)
// FreeBSD's strmode
void
strmode(/* mode_t */ int mode, char *p)
{
	 /* print type */
	switch (mode & S_IFMT) {
	case S_IFDIR:			/* directory */
		*p++ = 'd';
		break;
	case S_IFCHR:			/* character special */
		*p++ = 'c';
		break;
	case S_IFBLK:			/* block special */
		*p++ = 'b';
		break;
	case S_IFREG:			/* regular */
		*p++ = '-';
		break;
	case S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		break;
	case S_IFSOCK:			/* socket */
		*p++ = 's';
		break;
#ifdef S_IFIFO
	case S_IFIFO:			/* fifo */
		*p++ = 'p';
		break;
#endif
#ifdef S_IFWHT
	case S_IFWHT:			/* whiteout */
		*p++ = 'w';
		break;
#endif
	default:			/* unknown */
		*p++ = '?';
		break;
	}
	/* usr */
	if (mode & S_IRUSR)
		*p++ = 'r';
	else
		*p++ = '-';
	if (mode & S_IWUSR)
		*p++ = 'w';
	else
		*p++ = '-';
	switch (mode & (S_IXUSR | S_ISUID)) {
	case 0:
		*p++ = '-';
		break;
	case S_IXUSR:
		*p++ = 'x';
		break;
	case S_ISUID:
		*p++ = 'S';
		break;
	case S_IXUSR | S_ISUID:
		*p++ = 's';
		break;
	}
	/* group */
	if (mode & S_IRGRP)
		*p++ = 'r';
	else
		*p++ = '-';
	if (mode & S_IWGRP)
		*p++ = 'w';
	else
		*p++ = '-';
	switch (mode & (S_IXGRP | S_ISGID)) {
	case 0:
		*p++ = '-';
		break;
	case S_IXGRP:
		*p++ = 'x';
		break;
	case S_ISGID:
		*p++ = 'S';
		break;
	case S_IXGRP | S_ISGID:
		*p++ = 's';
		break;
	}
	/* other */
	if (mode & S_IROTH)
		*p++ = 'r';
	else
		*p++ = '-';
	if (mode & S_IWOTH)
		*p++ = 'w';
	else
		*p++ = '-';
	switch (mode & (S_IXOTH | S_ISVTX)) {
	case 0:
		*p++ = '-';
		break;
	case S_IXOTH:
		*p++ = 'x';
		break;
	case S_ISVTX:
		*p++ = 'T';
		break;
	case S_IXOTH | S_ISVTX:
		*p++ = 't';
		break;
	}
	*p++ = ' ';
	*p = '\0';
}
#endif

/*****************************************************************************
	siphash in C
*****************************************************************************/

/* <MIT License>
 Copyright (c) 2013  Marek Majkowski <marek@popcount.org>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 </MIT License>

 Original location:
    https://github.com/majek/csiphash/

 Solution inspired by code from:
    Samuel Neves (supercop/crypto_auth/siphash24/little)
    djb (supercop/crypto_auth/siphash24/little2)
    Jean-Philippe Aumasson (https://131002.net/siphash/siphash24.c)
*/

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
	__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define _le64toh(x) ((uint64_t)(x))
#elif defined(_WIN32)
/* Windows is always little endian, unless you're on xbox360
   http://msdn.microsoft.com/en-us/library/b0084kay(v=vs.80).aspx */
#  define _le64toh(x) ((uint64_t)(x))
#elif defined(__APPLE__)
#  include <libkern/OSByteOrder.h>
#  define _le64toh(x) OSSwapLittleToHostInt64(x)
#else

/* See: http://sourceforge.net/p/predef/wiki/Endianness/ */
#  if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#    include <sys/endian.h>
#  else
#    include <endian.h>
#  endif
#  if defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && \
	__BYTE_ORDER == __LITTLE_ENDIAN
#    define _le64toh(x) ((uint64_t)(x))
#  else
#    define _le64toh(x) le64toh(x)
#  endif

#endif


#define ROTATE(x, b) (uint64_t)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define HALF_ROUND(a,b,c,d,s,t)			\
	a += b; c += d;				\
	b = ROTATE(b, s) ^ a;			\
	d = ROTATE(d, t) ^ c;			\
	a = ROTATE(a, 32);

#define DOUBLE_ROUND(v0,v1,v2,v3)		\
	HALF_ROUND(v0,v1,v2,v3,13,16);		\
	HALF_ROUND(v2,v1,v0,v3,17,21);		\
	HALF_ROUND(v0,v1,v2,v3,13,16);		\
	HALF_ROUND(v2,v1,v0,v3,17,21);


uint64_t siphash24(const void *src, unsigned long src_sz, const char key[16]) {
	const uint64_t *_key = (uint64_t *)key;
	uint64_t k0 = _le64toh(_key[0]);
	uint64_t k1 = _le64toh(_key[1]);
	uint64_t b = (uint64_t)src_sz << 56;
	const uint64_t *in = (uint64_t*)src;

	uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
	uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
	uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
	uint64_t v3 = k1 ^ 0x7465646279746573ULL;

	while (src_sz >= 8) {
		uint64_t mi = _le64toh(*in);
		in += 1; src_sz -= 8;
		v3 ^= mi;
		DOUBLE_ROUND(v0,v1,v2,v3);
		v0 ^= mi;
	}

	uint64_t t = 0; uint8_t *pt = (uint8_t *)&t; uint8_t *m = (uint8_t *)in;
	switch (src_sz) {
	case 7: pt[6] = m[6];
	case 6: pt[5] = m[5];
	case 5: pt[4] = m[4];
	case 4: *((uint32_t*)&pt[0]) = *((uint32_t*)&m[0]); break;
	case 3: pt[2] = m[2];
	case 2: pt[1] = m[1];
	case 1: pt[0] = m[0];
	}
	b |= _le64toh(t);

	v3 ^= b;
	DOUBLE_ROUND(v0,v1,v2,v3);
	v0 ^= b; v2 ^= 0xff;
	DOUBLE_ROUND(v0,v1,v2,v3);
	DOUBLE_ROUND(v0,v1,v2,v3);
	return (v0 ^ v1) ^ (v2 ^ v3);
}


/*****************************************************************************
	Base64
*****************************************************************************/

/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
uint8_t *
base64_encode(const uint8_t *src, size_t len, size_t *out_len)
{
	uint8_t *out, *pos;
	const uint8_t *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	out = (uint8_t *)malloc(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	if (line_len)
		*pos++ = '\n';

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}

/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
uint8_t *
base64_decode(const uint8_t *src, size_t len, size_t *out_len)
{
	uint8_t	dtable[256], *out, *pos, block[4], tmp;
	size_t	i, count, olen;
	int	pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (uint8_t) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = (uint8_t *)malloc(olen);
	if (out == NULL) {
		return NULL;
	}

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=') {
			pad++;
		}
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					free(out);
					return NULL;
				}
				break;
			}
		}
	}

	*out_len = pos - out;

	return out;
}

/*****************************************************************************
	SSL
*****************************************************************************/

#if 0 // This doesn't work
int
SSL_read_all(SSL *ssl, void *data, int num)
{
	int	ret, sum = 0;

	for (;;) {
		// Receive anyway
		if ((ret = SSL_read(ssl, data, num)) < 0) {
			LogSSLError(__func__, ssl, ret);
			return -1;
		}
		else if (ret == 0) {
			break;
		}

		// Update sum
		sum += ret;

		// Check ret again
		if (ret < 16384) { // SSL data size
			break;
		}

		// Update parm
		num -= ret;
		data += ret;
//printf("sum = %d\n", sum);

/*
		// Check pending
		printf("SSL_has_pending: %d\n", SSL_has_pending(ssl));
		printf("SSL_pending: %d\n", SSL_pending(ssl));
		if (!SSL_has_pending(ssl)) {
			break;
		}
*/
	}

	return sum;
}
#endif

// Show data
void
ShowData(uint8_t *data, size_t len)
{
	uint8_t	*d = data, *d_end = data + len;

	while (d < d_end) {
		printf("%02x", *d);
		d++;
	}
	putchar('\n');
}

// Show data bytewisely
void
ShowBytes(const uint8_t *bytes, size_t len)
{
	size_t	idx;

	for (idx = 0; idx < len; idx++) {
		printf("%02x ", bytes[idx]);
	}
	putchar('\n');
}
