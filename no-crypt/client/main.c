/*
 *	All rights revserved by ASUSA Corporation and ASJ Inc.
 *	Copying any part of this program is prohibited.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#if defined(__FreeBSD__)
#include <libutil.h>
#endif
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define _MAIN_PROGRAM_
#include "common.h"
#include "parm-common.h"
#include "net.h"
#include "message.h"
#include "memory.h"
#include "net-common.h"
#include "misc-common.h"
#include "readconf.h"
#include "SFMT/SFMT.h"
#include "util.h"
#include "log.h"

/************************************************************
	Functions
************************************************************/

// Usage
static void
Usage()
{
	fprintf(stderr, "Usage: %s [-dhv]\n"
		"-d: Output debug messages\n"
		"-h: Show help message\n"
		"-v: Output verbose messages\n",
		Program);
	exit(1);
}

// At exit
static void
AtExit(void)
{
#if defined(__FreeBSD__)
	// Remove pid file -- This doesn't work caz uid != root
	if (PidFh != NULL) {
		pidfile_remove(PidFh);
	}
#endif
}

// At signal
static void
AtSignal(int sig)
{
	exit(0); // This also calls AtExit()
}

// Initialize 
void
Init(int argc, char **argv)
{
	char		*p;
	int		ch;

	// Save arguments
	Argc = argc;
	Argv = argv;

	// Get program name
	if ((p = strrchr(argv[0], '/')) != NULL) {
		p++;
		strncpy(Program, p, sizeof(Program));
	}
	else {
		strncpy(Program, argv[0], sizeof(Program));
	}

        // Get absolute path of program
	realpath(argv[0], ProgramPath);

	// Initialize some parameters
	umask(022); // I don't know if this is good
#if defined(__FreeBSD__)
	PidFh = NULL;
#endif
	Debug = 0;
	Verbose = 0;
	MyAddr = NULL;
	HsInfMeB = NULL;
	LocalHostAddr = inet_addr("127.0.0.1");
	InitConfig();

	// Get option
	while ((ch = getopt(argc, argv, "dhfl:v")) != -1) {
		switch (ch) {
		case 'd': // Debug
			Debug = 1;
			break;
		case 'v': // Verbose
			Verbose = 1;
			break;
		case 'h': // Help
		default:
			Usage();
		}
	}

	// Register atexit
	atexit(AtExit);

	// Initialize signals
	signal(SIGFPE, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
        signal(SIGKILL, AtSignal);
        signal(SIGINT, AtSignal);
        signal(SIGABRT, AtSignal);
	signal(SIGTERM, AtSignal);

#if defined(__FreeBSD__)
	//if (MyUid == 0) { // Only when run as root
		// Write pid to pid file
		if (PidFh != NULL) {
			pidfile_write(PidFh);
		}
	//}
#endif

	// Initialize log
	InitLog(NULL, Program, Daemon);
	//Log("%s: Launched", Program);

	// Set Uid if not yet
	if (Config.uid[0] == '\0') {
		strcpy(Config.uid, DEFAULT_USERNAME);
	}
}

// Main
int
main(int argc, char **argv)
{
	int		sock = 0, ret, num, i;
	int64_t		elapsed_ms;
	uint64_t	*data = NULL;
	uint64_t	reply_msg;
	struct timeval	start_tv, end_tv;

	// Initialize
	Init(argc, argv);

	// Connect
	if ((sock = ConnectToServer(DEFAULT_SERVER_NAME)) == -1) {
		exit(EXIT_FAILURE);
	}

	// Allocate data
	if ((data = aligned_alloc(32, GEN_DAT_SIZE)) == NULL) {
		Log("Error: %s: aligned_alloc data: %s",
			__func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Initialize random # generator
	sfmt_t	sfmt;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	sfmt_init_gen_rand(&sfmt, ts.tv_sec ^ ts.tv_nsec);

	// Input random values to data
	num = SEND_DAT_SIZE / sizeof(uint64_t);
	for (i = 0; i < num; i++) {
		data[i] = sfmt_genrand_uint64(&sfmt);
	}

	// Send original data
	if ((ret = write(sock, data, SEND_DAT_SIZE)) <= 0) {
		Log("Error: write: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
//ShowBytes((uint8_t *)data + SEND_DAT_SIZE - 128, 32);

	// Recv reply
	if ((ret = read(sock, &reply_msg, sizeof(uint64_t))) <= 0) {
		Log("Error: read: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	sleep(1);

	// Start measuring time
	gettimeofday(&start_tv, NULL);

	// Send data
	for (i = 0; i < SEND_REPEAT; i++) {
		// Send data
		if ((ret = WriteAll(sock, data, SEND_DAT_SIZE)) <= 0) {
			Log("Error: write: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	// Recv reply
	if ((ret = read(sock, &reply_msg, sizeof(uint64_t))) < 0) {
		Log("Error: read: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// End of encoding/decoding
	gettimeofday(&end_tv, NULL);

	// Get elapsed time
	elapsed_ms = (end_tv.tv_sec - start_tv.tv_sec) * 1000 +
			(end_tv.tv_usec - start_tv.tv_usec) / 1000;
	printf("Time: %f\nThroughput: %f Gbps\n",
		(double)elapsed_ms / 1000, (double)((SEND_DAT_SIZE /
		(1024 * 1024)) * SEND_REPEAT * 8) / (double)1024 *
		(double)1000 / (double)elapsed_ms);

	// Finalize
	if (sock > 0) {
		close(sock);
	}
	if (data != NULL) {
		free(data);
	}

	exit(0);
}
