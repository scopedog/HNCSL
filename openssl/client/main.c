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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#define _MAIN_PROGRAM_
#include "common.h"
#include "parm-common.h"
#include "net-common.h"
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
	MyAddr = NULL;
	HsInfMeB = NULL;
	LocalHostAddr = inet_addr("127.0.0.1");
	InitConfig();
	Config.port++;
	snprintf(Config.port_s, sizeof(Config.port_s), "%u", Config.port);

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

	// Set random seed
	clock_gettime(CLOCK_MONOTONIC, &ts);
	init_genrand64(ts.tv_nsec);

	// Set Uid if not yet
	if (Config.uid[0] == '\0') {
		strcpy(Config.uid, DEFAULT_USERNAME);
	}
}

// Connect
static int
Connect()
{
	int	err = 0;
	HInf	hInf;

	InitHInf(&hInf, DEFAULT_SERVER_NAME, NULL);
	if (ConnectToHost(&hInf, Config.port, 5000) == -1) {
		err = errno;
		Log("Error: %s: %s", __func__, strerror(errno));
		goto END;
	}

END:
	return err ? -1 : hInf.sock;
}

// AES-256 GCM key, etc
static const unsigned char gcm_key[] = {
	0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
	0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
	0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

static const unsigned char gcm_iv[] = {
	0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

static const unsigned char gcm_aad[] = {
	0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
	0x7f, 0xec, 0x78, 0xde
};

/*
static const unsigned char gcm_tag[] = {
	0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
	0x98, 0xf7, 0x7e, 0x0c
};
*/

// Encrypt with AES-256 GCM (from OpenSSL Wiki)
size_t
AES256_GCM_encrypt(unsigned char *plaintext, size_t plaintext_len,
            unsigned char *aad, size_t aad_len,
            unsigned char *key,
            unsigned char *iv, size_t iv_len,
            unsigned char *ciphertext,
            unsigned char *tag)
{
	EVP_CIPHER_CTX	*ctx;
	int		len;
	size_t		ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		return -1;
	}

	/* Initialise the encryption operation. */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		return -1;
	}

	/*
	 * Set IV length if default 12 bytes (96 bits) is not appropriate
	 */
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len,
				     NULL)) {
		return -1;
	}

	/* Initialise key and IV */
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
		return -1;
	}

	/*
	 * Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		return -1;
	}

	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len,
				   plaintext, plaintext_len)) {
		return -1;
	}
	ciphertext_len = len;

	/*
	* Finalise the encryption. Normally ciphertext bytes may be written at
	* this stage, but this does not occur in GCM mode
	*/
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		return -1;
	}
	ciphertext_len += len;

	/* Get the tag */
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
		return -1;
	}

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

// Decrypt with AES-256 GCM (from OpenSSL Wiki)
size_t
AES256_GCM_Decrypt(unsigned char *ciphertext, size_t ciphertext_len,
		   unsigned char *aad, size_t aad_len,
		   unsigned char *tag, unsigned char *key, unsigned char *iv,
		   unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len, ret;
	size_t plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		return -1;
	}

	/* Initialise the decryption operation. */
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		return -1;
	}

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) {
		return -1;
	}

	/* Initialise key and IV */
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
		return -1;
	}

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		return -1;
	}

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (!EVP_DecryptUpdate(ctx, plaintext, &len,
			       ciphertext, ciphertext_len)) {
		return -1;
	}
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
		return -1;
	}

	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if (ret > 0) {
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	}
	else {
		/* Verify failed */
		return -1;
	}
}

// Benchmark encrypt/decrypt speed
static int
BenchEncDecSpeed(uint8_t *data)
{
	int		len, i;
	uint8_t		*enc_dat, *dec_dat;
	EVP_CIPHER_CTX	*enc_ctx, *dec_ctx;
	struct timeval	start_tv, end_tv;

	// Initialize enc ctx
	enc_ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(enc_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv),
			NULL);
	EVP_EncryptInit_ex(enc_ctx, NULL, NULL, gcm_key, gcm_iv);
	EVP_EncryptUpdate(enc_ctx, NULL, &len, gcm_aad, sizeof(gcm_aad));

	// Initialize dec ctx
	dec_ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(dec_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv),
			NULL);
	EVP_DecryptInit_ex(dec_ctx, NULL, NULL, gcm_key, gcm_iv);
	EVP_DecryptUpdate(dec_ctx, NULL, &len, gcm_aad, sizeof(gcm_aad));

	// Allocate encrypted and decrypted data 
	if ((enc_dat = aligned_alloc(32, SEND_DAT_SIZE + 512)) == NULL) {
		Log("Error: %s: aligned_alloc enc_dat: %s",
			__func__, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if ((dec_dat = aligned_alloc(32, SEND_DAT_SIZE + 512)) == NULL) {
		Log("Error: %s: aligned_alloc dec_dat: %s",
			__func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Encrypt and decrypt
	gettimeofday(&start_tv, NULL); // Start benchmarking
	for (i = 0; i < BENCH_ENC_DEC_REPEAT; i++) {
		// Encrypt
		if (EVP_EncryptUpdate(enc_ctx, enc_dat, &len,
				data, SEND_DAT_SIZE) != 1) {
			Log("Error: %s: EVP_EncryptUpdate: %s",
				__func__, strerror(errno));
			return -1;
		}

		// Decrypt
		if (!EVP_DecryptUpdate(dec_ctx, dec_dat, &len,
				enc_dat, SEND_DAT_SIZE)) {
			Log("Error: %s: EVP_DecryptUpdate: %s",
				__func__, strerror(errno));
			return -1;
		}
	}

	// Finalize encryption
	if (EVP_EncryptFinal_ex(enc_ctx, enc_dat + len, &len) != 1) {
		return -1;
	}

	// Get the tag for encrypt
	if (EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_GET_TAG,
			16, enc_dat + len) != 1) {
		Log("Error: %s: EVP_CIPHER_CTX_ctrl EVP_CTRL_GCM_GET_TAG: %s",
			__func__, strerror(errno));
		return -1;
	}

	// Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if (!EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_TAG, 16,
			enc_dat + len)) {
		Log("Error: %s: EVP_CIPHER_CTX_ctrl EVP_CTRL_GCM_SET_TAG: %s",
			__func__, strerror(errno));
		return -1;
	}

	// Finalize decryption
	EVP_DecryptFinal_ex(dec_ctx, dec_dat + len, &len);

	// End benchmarking
	gettimeofday(&end_tv, NULL);

	// Get benchmark result
	int64_t	elapsed_ms = (end_tv.tv_sec - start_tv.tv_sec) * 1000 +
			(end_tv.tv_usec - start_tv.tv_usec) / 1000;
	printf("Encrypt/decrypt speed: %f Gbps\n",
		(double)((SEND_DAT_SIZE / (1024 * 1024)) *
		BENCH_ENC_DEC_REPEAT * 8 * 2) / (double)1024 * (double)1000 /
		(double)elapsed_ms);

	// Finalize
	EVP_CIPHER_CTX_free(enc_ctx);
	EVP_CIPHER_CTX_free(dec_ctx);

	return 0;
}

// Main
int
main(int argc, char **argv)
{
	// Initialize
	Init(argc, argv);

	int		sock = 0, ret, num, i;
	uint64_t	*data = NULL, reply_msg;
	//size_t		size;
	SSL_CTX		*ctx = NULL;
	X509		*cert = NULL;
	SSL		*ssl = NULL;
	const SSL_METHOD	*method;
	struct timeval	start_tv, end_tv;

	// Initialize SSL
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	if ((ret = SSL_library_init()) < 0) {
		LogSSLError("SSL_library_init", ssl, ret);
		exit(EXIT_FAILURE);
	}

	method = TLS_client_method();
	if (method == NULL) {
		LogSSLError("TLS_client_method", ssl, 0);
		exit(EXIT_FAILURE);
	}

	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		LogSSLError("SSL_CTX_new", ssl, 0);
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

	ssl = SSL_new(ctx);

	// Connect
	if ((sock = Connect()) == -1) {
		exit(EXIT_FAILURE);
	}
	SSL_set_fd(ssl, sock);

	// Connect with SSL
	if ((ret = SSL_connect(ssl)) != 1) {
		LogSSLError("SSL_connect", ssl, ret);
		exit(EXIT_FAILURE);
	}
	else if (Debug) {
		DebugMsg("SSL connected to %s\n", DEFAULT_SERVER_NAME);
	}

	// Get remote cert
	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		LogSSLError("SSL_get_peer_certificate", ssl, 0);
		exit(EXIT_FAILURE);
	}
	else {
		DebugMsg("Retrieved server's certificate from: %s.\n",
			DEFAULT_SERVER_NAME);
	}

	// Get cipher algorithm
	const SSL_CIPHER *cipher;

	cipher = SSL_get_current_cipher(ssl);
	printf("Cipher algorithm: %s\n", SSL_CIPHER_get_name(cipher));

/*
	// Show cert info
	if (Debug) {
		X509_NAME	*certname = NULL;

		// Extract various certificate information
		certname = X509_NAME_new();
		certname = X509_get_subject_name(cert);

		// Display cert subject
		puts("Certification Info:");
		X509_NAME_print_ex_fp(stdout, certname, 0, 0);
		putchar('\n');
	}
*/

	// Allocate data
	if ((data = aligned_alloc(32, GEN_DAT_SIZE)) == NULL) {
		Log("Error: %s: aligned_alloc: %s", __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Randomly input data
	num = SEND_DAT_SIZE / sizeof(uint64_t);
	for (i = 0; i < num; i++) {
		data[i] = genrand64_int64();
	}

	// Benchmark encryption/decryption speed
	BenchEncDecSpeed((uint8_t *)data);

	// Send data
	gettimeofday(&start_tv, NULL);
	for (i = 0; i < SEND_REPEAT; i++) {
		if ((ret = SSL_write(ssl, data, SEND_DAT_SIZE)) <= 0) {
			LogSSLError("SSL_write", ssl, ret);
			exit(EXIT_FAILURE);
		}
		if (ret != SEND_DAT_SIZE) {
			Log("Error: ret = %d != SEND_DAT_SIZE", ret);
			exit(EXIT_FAILURE);
		}
	}

	// Receive reply
	if ((ret = SSL_read(ssl, &reply_msg, sizeof(reply_msg))) == 0) {
		LogSSLError(__func__, ssl, ret);
		exit(EXIT_FAILURE);
	}

	gettimeofday(&end_tv, NULL);

	// Get elapsed time
	int64_t	elapsed_ms = (end_tv.tv_sec - start_tv.tv_sec) * 1000 +
			(end_tv.tv_usec - start_tv.tv_usec) / 1000;
	printf("Time: %f sec\nThroughput: %f Gbps\n",
		(double)elapsed_ms / 1000, (double)((SEND_DAT_SIZE /
		(1024 * 1024)) * SEND_REPEAT * 8) / (double)1024 *
		(double)1000 / (double)elapsed_ms);

	// Free SSL and close connection
	SSL_free(ssl);
	close(sock);
	X509_free(cert);
	SSL_CTX_free(ctx);

	exit(0);
}
