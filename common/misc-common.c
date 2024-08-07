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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <fts.h>
#include <dirent.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <libgen.h>
#include <netdb.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/socket.h>
#if defined(__FreeBSD__)
#include <sys/event.h>
#endif
#define _CORE_INC_CODE_STR
#include "common.h"
#undef _CORE_INC_CODE_STR
#include "parm-common.h"
#include "misc-common.h"
#include "net-common.h"
#include "mt64.h"
#include "log.h"
#include "util.h"

/************************************************************
	Functions
************************************************************/

// Open output file
FILE *
OpenFileW(const char *path)
{
	char		buf[PATH_MAX << 1], *p;
	mode_t		mode = S_IRUSR | S_IWUSR | S_IXUSR;
	FILE		*fp = NULL;
	struct stat	sb;

	strncpy(buf, path, sizeof(buf));
	p = (buf[0] == '/') ? buf + 1 : buf;

	// Recursively mkdir
	while ((p = strchr(p, '/')) != NULL) { // path includes directory
		*p = '\0';

		// Check dir
		if (lstat(buf, &sb) < 0) { // Dir cannot be opened
			if (mkdir(buf, mode) == -1 && errno != EEXIST) { // Err
				Log("Error: %s: mkdir %s: %s",
					__func__, buf, strerror(errno));
				return NULL;
			}
		}
		*p = '/';
		p++;
	}

	// Open
	if ((fp = fopen(path, "w")) == NULL) {
		// Error
		Log("Error: %s: fopen %s: %s", __func__, path, strerror(errno));
	}

	return fp;
}

// Open input file
FILE *
OpenFileR(const char *path)
{
	FILE	*fp;

	// Open - r+b actually opens with write enabled...
	if ((fp = fopen(path, "r+b")) == NULL) {
		// Error
		if (errno != ENOENT && (fp = fopen(path, "rb")) == NULL) {
			Log("Error: %s: fopen %s: %s",
				__func__, path, strerror(errno));
		}
	}

	return fp;
}

// Open output tmp file -- path must be like ".tmp.XXXXXXXX"
FILE *
OpenTmpFileW(char *path)
{
	char		buf[PATH_MAX << 1], *p, repeat = 0;
	int		fd = 0;
	FILE		*fp = NULL;
	struct stat	sb;

START:
	// Recursively mkdir
	strncpy(buf, path, sizeof(buf));
	p = buf;
	while (*p == '/') {
		p++;
	}
	while ((p = strchr(p, '/')) != NULL) { // path includes directory
		*p = '\0';

		// Check dir
		if (lstat(buf, &sb) == -1) { // Dir cannot be opened
			// Check error
			if (errno != ENOENT) {
				Log("Error: %s: lstat %s: %s",
					__func__, buf, strerror(errno));
				return NULL;
			}

			// Mkdir
//printf("%s: mkdir %s\n", __func__, buf);
			if (mkdir(buf, 0777) == -1 && errno != EEXIST) { // Err
				Log("Error: %s: mkdir %s: %s",
					__func__, buf, strerror(errno));
				return NULL;
			}
		}
		*p = '/';
		p++;
	}

	// Open
	if ((fd = mkstemp(path)) == -1) {
		// OK, I don't know why but this sometimes happens with FreeBSD
		// Let's do one more time
		if (!repeat) {
			repeat = 1;
			usleep(500000);
			goto START;
		}
		else {
			Log("Error: %s: mkstemp %s: %s",
				__func__, path, strerror(errno));
		}
// Debug
/*
{
	p = strrchr(path, '/');
	*p = '\0';
	if (lstat(path, &sb) == -1) {
		Log("Error: %s: lstat %s: %s",
			__func__, path, strerror(errno));
	}
	else {
		printf("%s exists\n", path);
	}
}
*/
		return NULL;
	}

	//if ((fp = fdopen(fd, "w")) == NULL) {
	if ((fp = fdopen(fd, "w+")) == NULL) {
		// Error
		Log("Error: %s: fdopen %s: %s",
			__func__, path, strerror(errno));
		close(fd);
	}

	return fp;
}

// Calculate st_blocks
blkcnt_t
GetStatBlocks(off_t fsize)
{
	blkcnt_t	b;

	// Return (sb->st_size / 32768) * (32768 / 512)
	b = fsize >> 15;
	if (fsize & ((2 << 16) - 1)) {
		b++;
	}
	b <<= 6;
         
	return b;
}

// Show checksum
void
ShowCheckSum(u_char *chkSum)
{
	int	i;

	for (i = 0; i < 32; i++) {
		printf("%02x", chkSum[i]);
	}
	putchar('\n');
}

// Check path
int
CheckPath(const char *path)
{
	// Check length
	if (strlen(path) > PATH_MAX - 2) {
		Log("Error: %s: path %s too long", __func__, path);
		errno = ENAMETOOLONG;
		return -1;
	}

	// Check path
	if (strncmp(path, "../", 3) == 0) { // path starts with ../
		Log("Error: %s: path %s starts with ../", __func__, path);
		errno = EPERM;
		return -1;
	}
	else if (strstr(path, "/../") != NULL) {
		Log("Error: %s: path %s includes /../", __func__, path);
		errno = EPERM;
		return -1;
	}

	return 0;
}

// Get uid of 'hncsl'
int
GetHncslUid(void)
{
	struct passwd   *sp;

	// Get uid
	if ((sp = getpwnam(DEFAULT_USERNAME)) == NULL) {
		Log("Error: Username \"%s\" cannot be found", DEFAULT_USERNAME);
		return -1;
	}

	// Change uid and gid
	HncslUid = sp->pw_uid;

	return 0;
}
