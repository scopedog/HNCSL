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

#ifndef _HNCSLD_SERVER_COMMON_H_
#define _HNCSLD_SERVER_COMMON_H_

// Prototypes
typedef struct _ThInf	ThInf;

#include "common.h"
#include "util.h"
#if defined(_HNC_)
#include "enc_dec.h"
#endif

/*********************************************************************
	Definitions
*********************************************************************/

#define MAX_CONNECTIONS	16
#define NUM_OF_RCVDAT	(MAX_CONNECTIONS << 1)

/*********************************************************************
	Structures
*********************************************************************/

// Thread info (ThInf) 
struct _ThInf {
	//Prog			prog; // Client program type
	int			sock; // Socket
	pthread_mutex_t		sockMutex; // Mutex for sock
	MyBool			sockMutexInit; // sockMutex already init'ed
	SSL			*ssl; // SSL
	HInfB			*hInfB; // Client that connected to me
	char			clName[MAXHOSTNAMELEN]; // Client name
	int			clFlg; // Client's hInfB->flg
	struct sockaddr_storage	addr; // Address
	char			ipAddrS[64]; // IP address in string
	char			buf[PATH_MAX * 2]; // General small buffer
	char			path[PATH_MAX]; // General file path
	char			basePath[PATH_MAX]; // Base path
	struct stat		sb; // Attributes
	int			err; // Error
	StrList			strList; // String list
#if defined(_HNC_)
	HNCdatS			*hncDat; // HNC data
#endif
	struct event_base	*evLoop; // libevent loop
	uint8_t			*rcvDat; // Buffer for receiving
	uint8_t			*sndDat; // BUffer for sending
};

/*********************************************************************
	Global varibales
*********************************************************************/

#ifdef _MAIN_PROGRAM_
#define EXTERN
#else
#define EXTERN extern
#endif

EXTERN struct pidfh	*PidFh; // Pid file handler
EXTERN ThInf		*ThrInf; // Thread info memory pool
EXTERN BitSet		*TIMap; // ThrInf memory usage map
EXTERN uint8_t		*RcvDat; // Data recv buffer
EXTERN BitSet		*RDMap; // RcvDat memory usage map
EXTERN pthread_mutex_t	TIMutex; // ThrInf mutex
EXTERN pthread_mutex_t	CIMutex; // CnnInf mutex
EXTERN pthread_mutex_t	RDMutex; // RcvDat mutex

#undef EXTERN

#endif // _HNCSLD_SERVER_COMMON_H_
