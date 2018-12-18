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


/* DECRYPT Lilliput (from v04 in FELICS) */
void DecryptLILLIPUT(uint8_t *block, uint8_t *roundKeys)
{
  uint8_t i;
  
  uint8_t tmpblock[16];
	from8To4Bits(tmpblock, block);
  /*29 rounds */
  for(i = 29 ; i > 0 ; i--)
  {
    uint8_t tmproundKeysi[8];

  	memcpy(tmproundKeysi, roundKeys + i*8, 8);
    
    /* NonLinearLayer + LinearLayer */
    
    tmpblock[8]  ^= (READ_SBOX_BYTE(S[tmpblock[7] ^    tmproundKeysi[ 0]]));
    tmpblock[9]  ^= (READ_SBOX_BYTE(S[tmpblock[6] ^    tmproundKeysi[ 1]]) ^ tmpblock[7]);
    tmpblock[10] ^= (READ_SBOX_BYTE(S[tmpblock[5] ^    tmproundKeysi[ 2]]) ^ tmpblock[7]);
    tmpblock[11] ^= (READ_SBOX_BYTE(S[tmpblock[4] ^    tmproundKeysi[ 3]]) ^ tmpblock[7]);
    tmpblock[12] ^= (READ_SBOX_BYTE(S[tmpblock[3] ^    tmproundKeysi[ 4]]) ^ tmpblock[7]);
    tmpblock[13] ^= (READ_SBOX_BYTE(S[tmpblock[2] ^    tmproundKeysi[ 5]]) ^ tmpblock[7]);
    tmpblock[14] ^= (READ_SBOX_BYTE(S[tmpblock[1] ^    tmproundKeysi[ 6]]) ^ tmpblock[7]);
    tmpblock[15] ^= (READ_SBOX_BYTE(S[tmpblock[0] ^    tmproundKeysi[ 7]]) ^ tmpblock[7] ^ tmpblock[6] ^ tmpblock[5] ^ tmpblock[4] ^ tmpblock[3] ^ tmpblock[2] ^ tmpblock[1]);
    
        
    /* PermutationLayer^-1 */
      
	uint8_t temp0 = tmpblock[0];
	tmpblock[0] = tmpblock[13];
	uint8_t temp1 = tmpblock[1];
	tmpblock[1] = tmpblock[9];
	uint8_t temp2 = tmpblock[2];
	tmpblock[2] = tmpblock[14];
	uint8_t temp3 = tmpblock[3];
	tmpblock[3] = tmpblock[8];
	uint8_t temp4 = tmpblock[4];
	tmpblock[4] = tmpblock[10];
	uint8_t temp5 = tmpblock[5];
	tmpblock[5] = tmpblock[11];
	uint8_t temp6 = tmpblock[6];
	tmpblock[6] = tmpblock[12];
	uint8_t temp7 = tmpblock[7];
	tmpblock[7] = tmpblock[15];
	
	tmpblock[8] = temp4;
	tmpblock[9] = temp5;
	tmpblock[10] = temp3;
	tmpblock[11] = temp1;
	tmpblock[12] = temp2;
	tmpblock[13] = temp6;
	tmpblock[14] = temp0;
	tmpblock[15] = temp7;
    
  } /* end round  */
    
  /* last round */
  uint8_t tmproundKeysi[8];
  memcpy(tmproundKeysi, roundKeys + i*8, 8);
  
  
  tmpblock[8]  ^= (READ_SBOX_BYTE(S[tmpblock[7] ^    tmproundKeysi[ 0]]));
  tmpblock[9]  ^= (READ_SBOX_BYTE(S[tmpblock[6] ^    tmproundKeysi[ 1]]) ^ tmpblock[7]);
  tmpblock[10] ^= (READ_SBOX_BYTE(S[tmpblock[5] ^    tmproundKeysi[ 2]]) ^ tmpblock[7]);
  tmpblock[11] ^= (READ_SBOX_BYTE(S[tmpblock[4] ^    tmproundKeysi[ 3]]) ^ tmpblock[7]);
  tmpblock[12] ^= (READ_SBOX_BYTE(S[tmpblock[3] ^    tmproundKeysi[ 4]]) ^ tmpblock[7]);
  tmpblock[13] ^= (READ_SBOX_BYTE(S[tmpblock[2] ^    tmproundKeysi[ 5]]) ^ tmpblock[7]);
  tmpblock[14] ^= (READ_SBOX_BYTE(S[tmpblock[1] ^    tmproundKeysi[ 6]]) ^ tmpblock[7]);
  tmpblock[15] ^= (READ_SBOX_BYTE(S[tmpblock[0] ^    tmproundKeysi[ 7]]) ^ tmpblock[7] ^ tmpblock[6] ^ tmpblock[5] ^ tmpblock[4] ^ tmpblock[3] ^ tmpblock[2] ^ tmpblock[1]);
	
  from4To8Bits(block, tmpblock);
}


void DecryptBLOCK(uint8_t *block, const uint8_t *key, const uint8_t *tweak){
	uint8_t roundkeys[ROUND_KEYS_SIZE];
	
	subkey(key, tweak, roundkeys);
	DecryptLILLIPUT(block, roundkeys);
}


/* ------------------------------------------------------------------------- */
int8_t ocb_decrypt( uint8_t *m, const uint8_t *key, const uint8_t *n,
                     const uint8_t *ad, uint32_t adlen,
                     const uint8_t *c, uint32_t clen) {
	uint32_t i, j;
	
	uint32_t mlen = clen-TAGBYTES;
	uint8_t tag[TAGBYTES];
	
	uint8_t tweak[TWEAK_SIZE];
	memset(tweak, 0, TWEAK_SIZE);
	
	
	/* HASH */
	uint8_t auth[8];
	memset(auth, 0, 8);
	
	for (i=1; i<=adlen/8; i++, ad = ad + 8) {
		uint8_t tmp[8];
		memcpy(tmp, ad, 8);
		
		update_tweak(tweak, 0x2, i-1);
		EncryptBLOCK(tmp, key, tweak);
		xor_block(auth, auth, tmp);
		
	}
	
	uint32_t remain = adlen%8;
	if (remain > 0) {
		uint8_t tmp[8];
		memset(tmp, 0, 8);
		memcpy(tmp, ad, remain);
		tmp[remain] = 0x80;
		
		update_tweak(tweak, 0x6, i-1);
		EncryptBLOCK(tmp, key, tweak);
		xor_block(auth, auth, tmp);
		
	}
	
	
	/* Decrypt */
	uint8_t checkSum[8];
	memset(checkSum, 0, 8);
	
	memset(tweak, 0, TWEAK_SIZE);
    set_nonce_in_tweak(tweak, n);
	
	
	/* begin decryption */
	for(i=1; i<=mlen/8; i++, m=m+8, c=c+8){
		memcpy(m, c, 8);
		update_tweak(tweak, 0x0, i-1);
		DecryptBLOCK(m, key, tweak);
		
		xor_block(checkSum, checkSum, m);
		
	}
	
	uint8_t final[8];
	//memset(final, 0, 8);
	
	remain = mlen%8;
	if(remain > 0){
		uint8_t pad[8];
		memset(pad, 0, 8);
		update_tweak(tweak, 0x4, i-1);
		EncryptBLOCK(pad, key, tweak);
		
		for(j=0; j<remain; j++){
			m[j] = c[j] ^ pad[j];
		}
		
		memset(pad, 0, 8);
		memcpy(pad, m, remain);
		pad[remain] = 0x80;
		xor_block(checkSum, checkSum, pad);
		
		memcpy(final, checkSum, 8);
		update_tweak(tweak, 0x5, i-1);
		EncryptBLOCK(final, key, tweak);
		
		
		c = c +remain;
		m = m +remain;
	}
	else{
		memcpy(final, checkSum, 8);
		update_tweak(tweak, 0x1, i-2);
		EncryptBLOCK(final, key, tweak);
	}
	
	
	xor_block(tag, final, auth);
	
	
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


