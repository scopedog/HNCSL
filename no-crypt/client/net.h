#ifndef _HNCSL_NET_H_
#define _HNCSL_NET_H_

#include <stdint.h>
#include <sys/stat.h>
#include "common.h"
#include "parm-common.h"
#include "net-common.h"

/*******************************************************************************
 	Definitions 
*******************************************************************************/
/*******************************************************************************
 	Structures 
*******************************************************************************/
/*******************************************************************************
 	Functions 
*******************************************************************************/

int	InitMyHostnameIP(void);
int	InitNet(void);
void	FinNet(void);
int	ConnectToServer(const char *);

#endif /* _HNCSL_NET_H_ */
