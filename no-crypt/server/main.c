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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define _MAIN_PROGRAM_
#define _MOD16_ // Dummy
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

#if 0
// Change uid
static void
ChangeUid(void)
{
	struct passwd	*sp;

	// Get uid 
	if ((sp = getpwnam(Config.uid)) == NULL) {
		Log("Error: Username \"%s\" cannot be found", Config.uid);
		exit(EXIT_FAILURE);
	}

	// Change uid and gid
	MyUid = sp->pw_uid;
	setuid(MyUid);
	setgid(sp->pw_gid);

/* fchown outputs "permission denied"
	// Change owner of pid file
	if (PidFh != NULL) {
		if (fchown(pidfile_fileno(PidFh), MyUid, 0) == -1) {
			Log("Warninig: chown pid file: %s", strerror(errno));
		}
	}
*/
}
#endif

// Initialize 
void
Init(int argc, char **argv)
{
	char	*p;
	int	ch;
#if defined(__FreeBSD__)
	char	buf[PATH_MAX];
	pid_t	exist_pid;
#endif

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
	Daemon = 0;
	MyAddr = NULL;
	HsInfMeB = NULL;
	LocalHostAddr = inet_addr("127.0.0.1");
	InitConfig();

	// Get option
	while ((ch = getopt(argc, argv, "dhDl:v")) != -1) {
		switch (ch) {
		case 'd': // Debug
			Debug = 1;
			break;
		case 'D': // Daemon mode
			Daemon = 1;
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

#if 0
	// Get home dir
	GetHomeDir();
#endif

#if defined(__FreeBSD__)
	// Open pid file
	snprintf(buf, sizeof(buf), "/var/run/%s.pid", Program);
	if ((PidFh = pidfile_open(buf, 0600, &exist_pid)) == NULL) {
		// Open failed
		if (errno == EEXIST) { // Process already running
			fprintf(stderr, "%s already running, pid: %d\n",
				Program, exist_pid);
			exit(EXIT_FAILURE);
		}
		else { // Other error
			fprintf(stderr, "Warning: Cannot open or create "
				"pidfile %s: %s\n", buf, strerror(errno));
		}
	}
#endif

	// Daemonize
	if (Daemon != 0) {
		//Daemonize(NULL); // This is not good for pidfile_*
		daemon(0, 0);
	}

#if defined(__FreeBSD__)
	//if (MyUid == 0) { // Only when run as root
		// Write pid to pid file
		pidfile_write(PidFh);
	//}
#endif

	// Initialize log
	InitLog(NULL, Program, Daemon);
	//Log("%s: Launched", Program);

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
