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

#include "cipher.h"
#include "constants.h"


#include <string.h>
#include <stdlib.h>



#define KEYBYTES   CRYPTO_KEYBYTES
#define NONCEBYTES CRYPTO_NPUBBYTES
#define TAGBYTES   CRYPTO_ABYTES





/* ------------------------------------------------------------------------- */
int8_t ocb_decrypt( uint8_t *m, const uint8_t *key, const uint8_t *n,
                     const uint8_t *ad, uint32_t adlen,
                     const uint8_t *c, uint32_t clen) {
	uint64_t i, j;
	
	uint32_t mlen = clen - TAGBYTES;
	uint8_t tag[16];
	
	uint8_t tweak[TWEAK_SIZE];
	memset(tweak, 0, TWEAK_SIZE);
	
	
	/* HASH */
	uint8_t auth[16];
	memset(auth, 0, 16);
	
	for (i=1; i<=adlen/16; i++, ad = ad + 16) {
		uint8_t tmp[16];
		memcpy(tmp, ad, 16);
		
		update_tweak(tweak, 0x2, i-1);
		EncryptBLOCK(tmp, key, tweak);
		xor_block(auth, auth, tmp);
		
	}
	
	uint32_t remain = adlen%16;
	if (remain > 0) {
		uint8_t tmp[16];
		memset(tmp, 0, 16);
		memcpy(tmp, ad, remain);
		tmp[remain] = 0x80;
		
		update_tweak(tweak, 0x6, i-1);
		EncryptBLOCK(tmp, key, tweak);
		xor_block(auth, auth, tmp);
		
	}
	
	
	/* Decrypt */
	uint8_t encr[16]; /* 00000000||n */
	memset(encr, 0, 16);
	memcpy( encr + 1, n, CRYPTO_NPUBBYTES);
	
	uint8_t tmp_tag[CRYPTO_ABYTES];
	memcpy(tmp_tag, c+mlen, CRYPTO_ABYTES);
	
	memset(tweak, 0, TWEAK_SIZE);
	memcpy(tweak, tmp_tag, CRYPTO_ABYTES );
    tweak[0] = 0x80 ^ (tweak[0] & 0x7f);
    
    uint8_t temp_tweak[16];
    memcpy( temp_tweak, tweak, 16 );
    	
	/* begin decryption */
	for(i=1; i<=mlen/16; i++, m=m+16, c=c+16){
		uint8_t tmp[16];
		memcpy(tmp, encr, 16);
		uptdate_tag_in_tweak(temp_tweak, tweak, i-1);
		EncryptBLOCK(tmp, key, temp_tweak);
		
		xor_block(m, c, tmp);
		
	}
	
	
	remain = mlen%16;
	if(remain > 0){
		uint8_t tmp[16];
		memcpy(tmp, encr, 16);	
		uptdate_tag_in_tweak(temp_tweak, tweak, i-1);
		EncryptBLOCK(tmp, key, temp_tweak);
		
		for(j=0; j<remain; j++){
			m[j] = c[j] ^ tmp[j];
		}
		
		c = c +remain;
		m = m +remain;
	}
	
	/* Tag Generation */
	memset(tweak, 0, TWEAK_SIZE);
	
	m = m - mlen;
	
	for(i=1; i<=mlen/16; i++, m=m+16){
		uint8_t tmp[16];
		memcpy(tmp, m, 16);
		update_tweak(tweak, 0x0, i-1);
		EncryptBLOCK(tmp, key, tweak);
		
		xor_block(auth, auth, tmp);
	}
	
	remain = mlen%16;
	if (remain > 0) {
		uint8_t tmp[16];
		memset(tmp, 0, 16);
		memcpy(tmp, m, remain);
		tmp[remain] = 0x80;
		
		update_tweak(tweak, 0x4, i-1);
		EncryptBLOCK(tmp, key, tweak);
		xor_block(auth, auth, tmp);
	}
	
	memcpy(tag, auth, 16);
	memset(tweak, 0, TWEAK_SIZE);
	offset_tweak(tweak, 0x1);
	memcpy( tweak + 1, n, CRYPTO_NPUBBYTES);
	EncryptBLOCK(tag, key, tweak); /* tag generated */
	
	int8_t result = (memcmp(c,tag,TAGBYTES) ? -1 : 0);     /* Check for validity */
	if ( result == 0 ){ /* Check for validity */
		return 0; /* valid*/
	} 
	return -1;    /* not valid*/
}

/* ------------------------------------ */

uint8_t crypto_aead_decrypt(
	uint8_t *m, uint32_t *mlen,
	uint8_t *nsec,
	const uint8_t *c, uint32_t clen,
	const uint8_t *ad, uint32_t adlen,
	const uint8_t *npub,
	uint8_t *k, uint8_t *roundKeys
	)
{
    *mlen = clen - TAGBYTES;
    
    uint8_t *cb;
	cb = (uint8_t *) malloc(clen * sizeof(uint8_t) );
	
	memcpy(cb, c, clen);
	uint8_t result = ocb_decrypt(m, k, npub,
            ad, adlen, cb, clen);
            
    free(cb);
    
    
    return result;
}



uint8_t Decrypt(uint8_t *block, int32_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, int32_t  adlen, uint8_t *c, uint8_t *roundKeys)
{

		static uint8_t *nsec;
	nsec = malloc(CRYPTO_NSECBYTES);
	
	//length of inputs and param
	uint32_t clen = mlen + CRYPTO_ABYTES;
	
	
	uint8_t *adb;
	adb = (uint8_t *) malloc(adlen * sizeof(uint8_t) );
	memcpy(adb, ad, adlen);
	
	if(adlen !=16){
	return crypto_aead_decrypt(
	block, (uint32_t*)&mlen,
	nsec,
	c, clen,
	adb, (uint32_t)adlen,
	npub,
	key, roundKeys
	);}
	else if(adlen ==16){
	return crypto_aead_decrypt(
	block, &mlen,
	nsec,
	c, clen,
	adb, adlen,
	npub,
	key, roundKeys
	);
	}
	
	free(adb);
	
}


