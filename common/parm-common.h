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

#ifndef _PARM_COMMON_H_
#define _PARM_COMMON_H_

/*********************************************************************
	Varibales
*********************************************************************/

#ifdef _MAIN_PROGRAM_
#define EXTERN
#else
#define EXTERN extern
#endif

// Command line arguments
EXTERN int	Argc;
EXTERN char	**Argv;
EXTERN int	Optind;

// Etc
EXTERN char		Program[PATH_MAX]; // Command name 
EXTERN char		ProgramPath[PATH_MAX]; // Program path 
EXTERN int		Command; // Command: see COM_GET, COM_PUT... above
EXTERN char		ComArg[MAX_COM_ARGS][PATH_MAX]; // Command arguments
EXTERN int		NumComArg; // # of ComArg
//EXTERN struct pidfh	*PidFh; // Pid file handler
EXTERN ConfigS		Config; // Global configuration
EXTERN uid_t		MyUid; // My uid
EXTERN uid_t		HncslUid; // My uid
EXTERN char		MyHostname[4096]; // My hostname
EXTERN in_addr_t	LocalHostAddr; // Local host IP address
EXTERN struct addrinfo	*MyAddr; // My IP addresses
EXTERN HInfB		*HsInfMeB; // My HInfB

#undef EXTERN

#endif // _PARM_COMMON_H_
