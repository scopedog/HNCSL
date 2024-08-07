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
#include "mod.h"
#include "enc_dec.h"
#include "net.h"
#include "message.h"
#include "memory.h"
#include "net-common.h"
#include "misc-common.h"
#include "readconf.h"
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

	// Initialize log
	InitLog(NULL, Program, Daemon);
	//Log("%s: Launched", Program);

/*
	srand(ts.tv_nsec);
	srandom(ts.tv_sec + ts.tv_nsec);
*/

	// Set Uid if not yet
	if (Config.uid[0] == '\0') {
		strcpy(Config.uid, DEFAULT_USERNAME);
	}
}

// Benchmark encrypt/decrypt speed
static void
BenchEncDecSpeed(HNCdatS *hnc_dat, void *data, void *enc_dat, void *dec_dat)
{
	int		i;
	struct timeval	start_tv, end_tv;

	gettimeofday(&start_tv, NULL); // Start benchmarking
	for (i = 0; i < BENCH_ENC_DEC_REPEAT; i++) {
		// Encrypt
		ResetHNCdatCod(hnc_dat); // Reset some parms
		HNCEncrypt(hnc_dat, data, enc_dat, SEND_DAT_SIZE);

		// Decrypt
		ResetHNCdatCod(hnc_dat); // Reset some parms
		HNCDecrypt(hnc_dat, dec_dat, dec_dat, SEND_DAT_SIZE);
	}

	// End benchmarking
	gettimeofday(&end_tv, NULL);

	// Get benchmark result
        int64_t elapsed_ms = (end_tv.tv_sec - start_tv.tv_sec) * 1000 +
			(end_tv.tv_usec - start_tv.tv_usec) / 1000;
	printf("Encrypt/decrypt speed: %f Gbps\n",
		(double)((SEND_DAT_SIZE / (1024 * 1024)) *
		BENCH_ENC_DEC_REPEAT * 8 * 2) / (double)1024 * (double)1000 /
		(double)elapsed_ms);

	// Reset some parms
	ResetHNCdatCod(hnc_dat);
}

// Main
int
main(int argc, char **argv)
{
	void		*enc_dat = NULL, *dec_dat;
	int		sock = 0, ret, num, i;
	int64_t		elapsed_ms;
	uint64_t	*data = NULL;
	uint64_t	reply_msg;
	size_t		size;
	struct timeval	start_tv, end_tv;
	HNCdatS		*hnc_dat = NULL;

	// Initialize
	Init(argc, argv);

	// Connect
	if ((sock = ConnectToServer(DEFAULT_SERVER_NAME)) == -1) {
		exit(EXIT_FAILURE);
	}

	// Allocate data
	if ((data = aligned_alloc(32, SEND_DAT_SIZE)) == NULL) {
		Log("Error: %s: aligned_alloc data: %s",
			__func__, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if ((enc_dat = aligned_alloc(32, SEND_DAT_SIZE)) == NULL) {
		Log("Error: %s: aligned_alloc enc_dat: %s",
			__func__, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if ((dec_dat = aligned_alloc(32, SEND_DAT_SIZE)) == NULL) {
		Log("Error: %s: aligned_alloc enc_dat: %s",
			__func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Allocate hnc_dat
	if ((hnc_dat = AllocHNCdat()) == NULL) {
		Log("Error: %s: AllocHNCdat: %s", __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Input random values to data
	sfmt_t	*sfmt = &hnc_dat->sfmt;
	num = SEND_DAT_SIZE / sizeof(uint64_t);
	for (i = 0; i < num; i++) {
		data[i] = sfmt_genrand_uint64(sfmt);
	}

#if 1 // Debug
	if (HNCTestEncDec() == -1) {
		// Error
		exit(EXIT_FAILURE);
	}
#endif

	// Generate random keys
	GenHNCkey(hnc_dat);
	//SetSampleHNCkey(hnc_dat);

	// Show keys
	//ShowHNCkey(hnc_dat);

	// Benchmark encryption/decryption speed
	BenchEncDecSpeed(hnc_dat, data, enc_dat, dec_dat);

	// Copy keys to enc_dat
	size = SetKeys(hnc_dat, enc_dat);

	// Send keys
	if ((ret = write(sock, enc_dat, size)) <= 0) {
		Log("Error: write: %s", strerror(errno));
		exit(EXIT_FAILURE);
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

	// Encrypt and send data
	for (i = 0; i < SEND_REPEAT; i++) {
		// Encrypt
		HNCEncrypt(hnc_dat, data, enc_dat, SEND_DAT_SIZE);

		// Send encrypt data
		if ((ret = WriteAll(sock, enc_dat, SEND_DAT_SIZE)) <= 0) {
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
	if (enc_dat != NULL) {
		free(enc_dat);
	}
	if (hnc_dat != NULL) {
		FreeHNCdat(hnc_dat);
	}

	exit(0);
}
