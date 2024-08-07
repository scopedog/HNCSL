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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define _MAIN_PROGRAM_
#include "common.h"
#include "parm-common.h"
#include "server-common.h"
#include "net.h"
#include "memory.h"
#include "misc-common.h"
#include "readconf.h"
#include "mt64.h"
#include "util.h"
#include "log.h"


/************************************************************
	Functions
************************************************************/

// Usage
static void
Usage()
{
	fprintf(stderr, "Usage: %s [-dfhv]\n"
		"-d: Output debug messages\n"
		"-f: Run in foreground\n"
		"-h: Show help message\n"
		"-v: Output verbose messages\n",
		Program);
	exit(1);
}

// At exit
static void
AtExit(void)
{
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
	struct timespec	ts;

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
	Debug = 0;
	Verbose = 0;
	Daemon = 0;
	MyAddr = NULL;
	HsInfMeB = NULL;
	LocalHostAddr = inet_addr("127.0.0.1");
	InitConfig();
	Config.port++;
	snprintf(Config.port_s, sizeof(Config.port_s), "%u", Config.port);

	// Get option
	while ((ch = getopt(argc, argv, "dDhfl:v")) != -1) {
		switch (ch) {
		case 'd': // Debug
			Debug = 1;
			break;
		case 'D': // Daemon
			Daemon = 1;
			break;
		case 'f': // Run in foreground
			Daemon = 0;
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

	// Daemonize
	if (Daemon) {
		//Daemonize(NULL); // This is not good for pidfile_*
		daemon(0, 0);
	}

	// Initialize log
	InitLog(NULL, Program, Daemon);
	//Log("%s: Launched", Program);

	// Set random seed
	clock_gettime(CLOCK_MONOTONIC, &ts);
	init_genrand64(ts.tv_nsec);
/*
	srand(ts.tv_nsec);
	srandom(ts.tv_sec + ts.tv_nsec);
*/

	// Set Uid if not yet
	if (Config.uid[0] == '\0') {
		strcpy(Config.uid, DEFAULT_USERNAME);
	}

	// Initialize my hostname and IP addresses
	if (InitMyHostnameIP() == -1) {
		exit(1);
	}

	// Initialize memory
	InitMem();

	// Initialize net
	InitNet();
}

// Main
int
main(int argc, char **argv)
{
	// Initialize
	Init(argc, argv);

	// Main loop
	LoopNet();

	exit(0);
}
