/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu> and 
 * Yann Le Corre <yann.lecorre@uni.lu>
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
#include "constants.h"
#include "cipher.h"
#include "common.h"


#if defined(PC) && defined(MEASURE_CYCLE_COUNT) && \
	(MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT)
#include <stdio.h>
#include <inttypes.h>
#include "cycleCount.h"
#endif /* PC & MEASURE_CYCLE_COUNT */

#if defined(ARM) && defined(MEASURE_CYCLE_COUNT) && \
	(MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT)
#include <sam3x8e.h>
#include <stdio.h>
#include <unistd.h>
#include "cycleCount.h"
#endif /* ARM & MEASURE_CYCLE_COUNT */

#if defined(ARM) && defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
#include <stdio.h>
#endif /* ARM & DEBUG */


/*
 *
 * Entry point into program
 *
 */
int main()
{
	RAM_DATA_BYTE state[MAXTEST_BYTES_M];

	RAM_DATA_BYTE key[KEY_SIZE];
	
/* ----------------------------------------- */	
	RAM_DATA_BYTE c[MAXTEST_BYTES_M  + CRYPTO_ABYTES]; // contains the cipher text THEN the tag value
	
	RAM_DATA_BYTE ad[MAXTEST_BYTES_AD];
	
	RAM_DATA_BYTE npub[CRYPTO_NPUBBYTES];
/* ----------------------------------------- */		


	InitializeDevice();	
	
		
	InitializeState(state);

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	DisplayVerifyData(state, MAXTEST_BYTES_M, PLAINTEXT_NAME);
#endif
	
	InitializeKey(key);

#if defined(DEBUG) && (DEBUG_MEDIUM == (DEBUG_MEDIUM & DEBUG))
	DisplayVerifyData(key, KEY_SIZE, KEY_NAME);
#endif

/* ----------------------------------------- */	
	InitializeAd(ad, MAXTEST_BYTES_AD);
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	DisplayVerifyData(ad, MAXTEST_BYTES_AD, ASSOCIATED_NAME);
#endif
	
	InitializeNpub(npub);
/* ----------------------------------------- */	

	BEGIN_ENCRYPTION();
	Encrypt(state, MAXTEST_BYTES_M, key, npub, ad, MAXTEST_BYTES_AD, c);
	END_ENCRYPTION();

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	DisplayVerifyData(c, MAXTEST_BYTES_M  + CRYPTO_ABYTES, CIPHERTEXT_NAME);
#endif
	
	BEGIN_DECRYPTION();
	int valid = Decrypt(state, MAXTEST_BYTES_M, key, npub, ad, MAXTEST_BYTES_AD, c);
	END_DECRYPTION();

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	DisplayVerifyData(state, MAXTEST_BYTES_M, PLAINTEXT_NAME);
#endif
	
	
	DONE();


	StopDevice();
	
	
	return valid;
}
