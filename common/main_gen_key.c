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
	This program outputs HNC keys so they can be used as a header file
	(xxxx.h).
	Well, it will be helpful to output something like a08f4d1058ad42....
	just like one used in SSL, SSH key files, but it's not implemented yet.
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
#if defined(__FreeBSD__)
#include <libutil.h>
#endif
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#define _MAIN_PROGRAM_
#include "main.h"
#include "common.h"
#include "enc_dec.h"
#include "util.h"
#include "log.h"

/************************************************************
	Functions
************************************************************/

#if 0
// Usage
static void
Usage()
{
	fprintf(stderr, "Usage: %s\n", Program);
	exit(1);
}
#endif

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

// Initialize - We don't actually need this for this program
static void
Init(int argc, char **argv)
{
	char	*p;
	//int	ch;

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

#if 0
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
#endif

	// Register atexit
	atexit(AtExit);

	// Initialize signals
	signal(SIGFPE, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
        signal(SIGKILL, AtSignal);
        signal(SIGINT, AtSignal);
        signal(SIGABRT, AtSignal);
	signal(SIGTERM, AtSignal);
}

// Main
int
main(int argc, char **argv)
{
	HNCdatS	*hnc_dat = NULL;

	// Initialize
	Init(argc, argv);

	// Allocate hnc_dat
	if ((hnc_dat = AllocHNCdat()) == NULL) {
		Log("Error: %s: AllocHNCdat: %s", __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}


	// Generate random keys
	GenHNCkey(hnc_dat);

	// Show keys
	ShowHNCkey(hnc_dat);

	// Finalize
	if (hnc_dat != NULL) {
		FreeHNCdat(hnc_dat);
	}

	exit(0);
}
