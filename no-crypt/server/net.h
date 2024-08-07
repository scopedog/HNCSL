#ifndef _HNCSLD_NET_H_
#define _HNCSLD_NET_H_

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
void	InitNet(void);
void	LoopNet(void);
int	SendError(ThInf *, const char *, int);


#endif /* _HNCSLD_NET_H_ */
