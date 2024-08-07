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
/******************************************************************************
*
*	PROGRAM  : log.c
*	LANGUAGE : C
*	REMARKS  : Functions regarding log.
*	AUTHOR   : Hiroshi Nishida
*	COPYRIGHT: Copyright (C) 2006- ASUSA, ASJ
*
*******************************************************************************/

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"

#if defined(__linux__)
#define _GNU_SOURCE
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifndef __WIN32__
#include <grp.h>
#endif
#include "util.h"

static int	LogFd = 2;
static char	LogFile[PATH_MAX];
static size_t	LogFileLen = 0;

#ifndef	True
#define True		1
#endif
#ifndef	False
#define False		0
#endif
#define	LOGPERM		( S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)
#define MAXLOGSZ	100000

/*****************************************************************/

/* Vfprintf error messages */
static void
Cmnerr(const char *fmt, va_list ap)
{
	int		err;

	/* Save errno */
	err = errno;

	/* Output error message */
	vfprintf(stderr, fmt, ap);
	if (err != 0)
		fprintf(stderr, ": %s", strerror(err));
	putc('\n', stderr);
}

/* Output error message and exit */
void
Fatal(const char *fmt,...)
{
	va_list		ap;

	va_start(ap, fmt);
	Cmnerr(fmt, ap);
	va_end(ap);
	exit(1);
}

/* Initialize log file */
int
InitLog(char *logfile, char *command, int daemonflg)
{
	struct stat	sbuf;
	struct group   *gp;
	int		fl;

	if (daemonflg) {
		/* Set log file */
		if (logfile == NULL) {
			if (command == NULL) {
				fprintf(stderr, "Error: InitLog(): "
					"arg 2 must be non NULL");
				exit(EXIT_FAILURE);
			}

			// Automatically set file name from command
			snprintf(LogFile, sizeof(LogFile), "/var/log/%s.log",
				command);
			logfile = LogFile;
		}
		else {
			strncpy(LogFile, logfile, sizeof(LogFile));
			LogFile[PATH_MAX - 1] = '\0';
		}

		/* Check length of LogFile */
		if ((LogFileLen = strlen(LogFile)) > PATH_MAX - 32) {
			// Too long
			fprintf(stderr, "Error: Log filename too long\n");
			exit(EXIT_FAILURE);
		}

		/* Open log file */
		if ((LogFd = open(logfile,
				O_WRONLY | O_APPEND | O_CREAT, LOGPERM)) < 0) {
			snprintf(LogFile, sizeof(LogFile), "%s.log", command);
			logfile = LogFile;
			if ((LogFd = open(logfile,
				O_WRONLY | O_APPEND | O_CREAT, LOGPERM)) < 0) {
				fprintf(stderr, "Error: InitLog: open %s: %s",
					logfile, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}

		/* Set "close-on-exec" flag */
		if ((fl = fcntl(LogFd, F_GETFD, 0)) < 0 ||
	    	(fcntl(LogFd, F_SETFD, fl | FD_CLOEXEC) < 0)) {
			close(LogFd);
			LogFd = -1;
			return -1;
		}

		/* Get "daemon" group ID */
		if ((gp = getgrnam("daemon")) == NULL) {
			close(LogFd);
			LogFd = -1;
			errno = EINVAL;
			return -1;
		}
		/*
	 	* Change user ID and group ID if the owner of the log file 			* is not root or its group is not daemon
	 	*/
		if (fstat(LogFd, &sbuf) < 0) {
			close(LogFd);
			LogFd = -1;
			return -1;
		}
		if ((sbuf.st_uid != 0) || (sbuf.st_gid != gp->gr_gid)) {
			if (fchown(LogFd, 0, gp->gr_gid) == -1) {
				fprintf(stderr, "Warning: fchown %s: %s\n",
					logfile, strerror(errno));
			}
		}
	}
	else {
		LogFd = STDERR_FILENO; // stderr
	}

	return 0;
}

// Log
void
Log(const char *fmt,...)
{
	time_t		t;
	char           *tm, *p;
	struct stat	sbuf;
	va_list		ap;
	char		buf[BUFSIZ];

	/* Obtain the current time and convert to string */
	time(&t);
	tm = ctime(&t);

	/* Conver '\n' to space and copy to buffer */
	tm[24] = ':';
	strcat(tm, " ");
	strncpy(buf, tm, 26);

	/* Concatenate fmt to buf */
	va_start(ap, fmt);
	p = buf + 26;
	vsnprintf(p, sizeof(buf) - 26, fmt, ap);
	va_end(ap);

	/* Concatenate '\n' */
	strcat(buf, "\n");

	/* If the size of log file is too big, save it as a gzipped file */
	if (fstat(LogFd, &sbuf) == 0) {
		if (sbuf.st_size > MAXLOGSZ) {
			time_t		_t = time(NULL);
			struct tm	*t = localtime(&_t);
			char		bkup_file[PATH_MAX], buf2[BUFSIZ], *p;

			/* Set file name */
#if defined(__APPLE__) && defined(__MACH__)
			memcpy(bkup_file, LogFile, LogFileLen);
			p = &bkup_file[LogFileLen];
#else

			p = mempcpy(bkup_file, LogFile, LogFileLen);
#endif
			snprintf(p, 31, "-%04d%02d%02d-%02d%02d%02d",
				t->tm_year + 1900, t->tm_mon + 1,
				t->tm_mday, t->tm_hour, t->tm_min,
				t->tm_sec);

			/* Copy LogFile to bkup_file */
			snprintf(buf2, sizeof(buf2) - 1, "cp %s %s",
				 LogFile, bkup_file);
			if (system(buf2)) {
				if (write(LogFd, "Warning: Failed: ",
					strlen("Warning: Failed: ")) == -1) {
					fprintf(stderr,
						"Error: Log: write: %s\n",
						strerror(errno));
				}
				if (write(LogFd, buf2, strlen(buf2)) == -1) {
					fprintf(stderr,
						"Error: Log: write: %s\n",
						strerror(errno));
				}
				if (write(LogFd, "\n", 1) == -1) {
					fprintf(stderr,
						"Error: Log: write: %s\n",
						strerror(errno));
				}
			}

			/* Gzip bkup_file */
			snprintf(buf2, sizeof(buf2), "gzip -f -q %s &",
				bkup_file);
			if (system(buf2)) {
				if (write(LogFd, "Warning: Failed: ",
					strlen("Warning: Failed: ")) == -1) {
					fprintf(stderr,
						"Error: Log: write: %s\n",
						strerror(errno));
				}
				if (write(LogFd, buf2, strlen(buf2)) == -1) {
					fprintf(stderr,
						"Error: Log: write: %s\n",
						strerror(errno));
				}
				if (write(LogFd, "\n", 1) == -1) {
					fprintf(stderr,
						"Error: Log: write: %s\n",
						strerror(errno));
				}
			}

			/* Reset log file */
			if (ftruncate(LogFd, 0) == -1) {
				fprintf(stderr, "Error: Log: ftruncate: %s\n",
					strerror(errno));
			}
		}
	}

	/* Write message to log file */
	if (write(LogFd, buf, strlen(buf)) == -1) {
		fprintf(stderr, "Error: Log: write: %s\n", strerror(errno));
	}

	/* Write message to stderr */
/*
	if (!Daemon) {
		if (write(2, p, strlen(p)) == -1) {
			fprintf(stderr, "Error: Log: write: %s\n",
				strerror(errno));
		}
	}
*/
}

#if defined(LOG_SSL_ERROR)
// Log SSL error
void
LogSSLError(const char *str, SSL *ssl, int ret)
{
#if 0
	char	*ptr = NULL, buf[BUFSIZ];
	size_t	len;
	BIO	*bio = BIO_new(BIO_s_mem());

	//ERR_print_errors(bio);
	len = BIO_get_mem_data(bio, &ptr);
	strncpy(buf, ptr, len);
	buf[len] = '\0';
	Log("Error: %s: %s", str, buf);
	BIO_free(bio);

#else
	int	err;

	//Log("Error: %s: %s", str, ERR_error_string(ERR_get_error(), NULL));
	err = SSL_get_error(ssl, ret);
	switch (err) {
	case SSL_ERROR_NONE:
		Log("Info: %s: No SSL errors", str);
		break;
	case SSL_ERROR_ZERO_RETURN:
		Log("Error: %s: Peer closed the connection", str);
		break;
	case SSL_ERROR_WANT_READ:
		Log("Error: %s: SSL wants to read", str);
		break;
	case SSL_ERROR_WANT_X509_LOOKUP:
		Log("Error: %s: SSL_ERROR_WANT_X509_LOOKUP", str);
		break;
/* The followings are not suppoted by boringssl
	case SSL_ERROR_WANT_ASYNC:
		Log("Error: %s: SSL_ERROR_WANT_ASYNC", str);
		break;
	case SSL_ERROR_WANT_ASYNC_JOB:
		Log("Error: %s: SSL_ERROR_WANT_ASYNC_JOB", str);
		break;
	case SSL_ERROR_WANT_CLIENT_HELLO_CB:
		Log("Error: %s: SSL_ERROR_WANT_CLIENT_HELLO_CB", str);
		break;
*/
	case SSL_ERROR_SYSCALL:
		Log("Error: %s: SSL_ERROR_SYSCALL", str);
		//Log("Error: %s: %s", str, strerror(errno));
		break;
	case SSL_ERROR_SSL:
		Log("Error: %s: SSL_ERROR_SSL", str);
		break;
	default:
		Log("Error: %s: Unknown SSL error: %d", str, err);
		break;
	}
#endif
}
#endif
#pragma clang diagnostic pop
