/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"

void permutation(uint8_t *tab){
	uint32_t tmp[2];
	memcpy(tmp, tab, 8);
	
	tab[0]= tab[9];
	tab[1]= tab[15];
	tab[2]= tab[8];
	tab[3]= tab[13];
	tab[4]= tab[10];
	tab[5]= tab[14];
	tab[6]= tab[12];
	tab[7]= tab[11];
	
	memcpy(tab+8, tmp, 8);
	
}


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	
  	uint8_t TK1[16];
	uint8_t TK2[16];
	
	
	
	memcpy(TK1, key, 16);
	memcpy(TK2, key+16, 16);
	
	int32_t i, j;
	for(i=0; i<29; i++){
		/*Extract RK */
		
		((uint32_t *)(void *)roundKeys)[0+ i*2] = ((uint32_t *)(void *)TK1)[0] ^ ((uint32_t *)(void *)TK2)[0] ;
		((uint32_t *)(void *)roundKeys)[1+ i*2] = ((uint32_t *)(void *)TK1)[1] ^ ((uint32_t *)(void *)TK2)[1] ;
		
		/* State Tweakey update - Permutation + LSFR */
		permutation(TK1);
		permutation(TK2);
		
		for(j = 0 ; j < 8 ; j++){
			TK2[j] = ((TK2[j]<<1)&0xE) ^ ((TK2[j]>>3)&0x1) ^ ((TK2[j]>>2)&0x1);
		}
		
	}
	
	((uint32_t *)(void *)roundKeys)[0+ i*2] = ((uint32_t *)(void *)TK1)[0] ^ ((uint32_t *)(void *)TK2)[0] ;
	((uint32_t *)(void *)roundKeys)[1+ i*2] = ((uint32_t *)(void *)TK1)[1] ^ ((uint32_t *)(void *)TK2)[1] ;
  
}
