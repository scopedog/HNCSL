#ifndef _MOD_MTRX_H_
#define _MOD_MTRX_H_

#include <stdint.h>

/*********************************************************************
	Definitions
*********************************************************************/

/*********************************************************************
	Functions
*********************************************************************/

// 8bit
void	Mod8MtrxByVct(uint8_t **, uint8_t *, uint8_t *, int);
void	Mod8MtrxByMtrx(uint8_t **, uint8_t **, uint8_t **, int);
int	Mod8InvMtrx(uint8_t **, uint8_t **, int);
int	Mod8TestMtrx(void);

// 16bit
void	Mod16MtrxByVct(uint16_t **, uint16_t *, uint16_t *, int);
void	Mod16MtrxByMtrx(uint16_t **, uint16_t **, uint16_t **, int);
int	Mod16InvMtrx(uint16_t **, uint16_t **, int);
void	Mod16ShowMtrx3(uint16_t (*)[3]);
void	Mod16MtrxByVct3(uint16_t (*)[3], uint16_t *, uint16_t *);
void	Mod16MtrxByMtrx3(uint16_t (*)[3], uint16_t (*)[3], uint16_t (*)[3]);
int	Mod16InvMtrx3(uint16_t (*)[3], uint16_t (*)[3]);
int	Mod16TestMtrx(void);

// 32bit
void	Mod32MtrxByVct(uint32_t **, uint32_t *, uint32_t *, int);
void	Mod32MtrxByMtrx(uint32_t **, uint32_t **, uint32_t **, int);
int	Mod32InvMtrx(uint32_t **, uint32_t **, int);
void	Mod32ShowMtrx3(uint32_t (*)[3]);
void	Mod32MtrxByVct3(uint32_t (*)[3], uint32_t *, uint32_t *);
void	Mod32MtrxByMtrx3(uint32_t (*)[3], uint32_t (*)[3], uint32_t (*)[3]);
int	Mod32InvMtrx3(uint32_t (*)[3], uint32_t (*)[3]);
int	Mod32TestMtrx(void);

#endif // _MOD_MTRX_H_
