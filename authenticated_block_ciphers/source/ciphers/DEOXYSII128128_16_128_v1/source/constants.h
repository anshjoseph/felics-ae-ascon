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

#ifndef CONSTANTS_H
#define CONSTANTS_H

#include "data_types.h"


/*
 *
 * Cipher characteristics:
 * 	BLOCK_SIZE - the cipher block size in bytes
 * 	KEY_SIZE - the cipher key size in bytes
 *	ROUND_KEY_SIZE - the cipher round keys size in bytes
 * 	NUMBER_OF_ROUNDS - the cipher number of rounds
 *
 */
#define KEY_SIZE 16
#define ROUND_KEYS_SIZE 0

#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 15
#define CRYPTO_ABYTES 16


/*
 *
 * Cipher constants
 *
 */
/* Replace with the cipher constants declaration */

/* Define the three MSB of the tweak (that depend on the stage) */
#define MSB_AD_N1		      (0x3<<4)
#define MSB_AD_N2		      (0x7<<4)
#define MSB_AD 			      (0x2<<4)
#define MSB_AD_LAST		      (0x6<<4)
#define MSB_M			      (0x0<<4)
#define MSB_M_LAST_ZERO		      (0x1<<4)
#define MSB_M_LAST_NONZERO	      (0x4<<4)
#define MSB_CHKSUM		      (0x5<<4)

/* Number of bits in the TWEAKEY state (256 or 384) */
#define TWEAKEY_STATE_SIZE    256


extern TW_DOUBLE_WORD Te0[256];
extern TW_DOUBLE_WORD Te1[256];
extern TW_DOUBLE_WORD Te2[256];
extern TW_DOUBLE_WORD Te3[256];
extern TW_DOUBLE_WORD Te4[256];

extern TW_DOUBLE_WORD Td0[256];
extern TW_DOUBLE_WORD Td1[256];
extern TW_DOUBLE_WORD Td2[256];
extern TW_DOUBLE_WORD Td3[256];
extern TW_DOUBLE_WORD Td4[256];

extern PERM_BYTE perm[16];

extern RCON_BYTE rcon[17];

extern LFSR_BYTE lfsr2[256];
extern LFSR_BYTE lfsr4[256];


#endif /* CONSTANTS_H */
