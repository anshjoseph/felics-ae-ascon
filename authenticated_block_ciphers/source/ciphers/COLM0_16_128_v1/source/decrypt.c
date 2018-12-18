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

//#include "module.h"

#include <string.h>
#include <stdlib.h>



#define alpha_128 0x87 // Denotes the primitive polynomial x^128+x^7+x^2+x+1
#define AD 0
#define MESSAGE 1
#define CIPHERTEXT 2
#define ENCRYPT 1
#define DECRYPT 0
#define IT_MAX 32  // This denotes the maximum no. of intermediate tag blocks generated. It is required for  intermediated tag versions only.  We provide intermediate tags upto message length of 2^16 bytes. As we generate intermediate tags after 127 blocks, maximum floor(2^12/127) = 32 blocks of intermediate tags can be generated. So, corresponding ABYTES value will be 536 (= 2^4*32+24) for fixed versions using intermediate tags and 552 (= 2^4*32+40) for flexible version. 


typedef uint8_t block[16];


//uint8_t tab1[16];
//uint8_t tab0[16];

void load_block_AD(block L, const uint8_t *a1, const uint8_t *a2, uint8_t len1){
  	uint8_t len2 = 16-len1;
	uint8_t i; for(i=0; i<len1; i++)	{L[i] = a1[i];}	
	for(i=0; i<len2; i++)	{L[i+len1] = a2[i];}
	if(len1 + len2 < 16)	{L[len1+len2]=0x80; for(i=len2+len1+1; i<16; i++) L[i]=0x00;}  
	
	
	}

static void process_AD(
	block W, block Delta_1, const block npub, block param, 
	const uint8_t *ad, int32_t adlen, uint8_t *roundKeys) {	

	block Delta_2, blk, result;
	uint8_t Is_Final = 0, ozs[16];
	uint8_t i; for(i=1; i<16; i++){ozs[i]=0x00;} ozs[0] = 0x80; 

	

	/* ===== make the first block blk based on npub and param ===== */
	load_block(blk, npub, param, 8, 8);
	
	
	
	i = 0;
	while(1){ 
		//uint8_t *roundkeysb;
		//roundkeysb = (uint8_t *) malloc(ROUND_KEYS_SIZE * sizeof(uint8_t) );
		
		uint8_t roundkeysb[ROUND_KEYS_SIZE];
		memcpy(roundkeysb, roundKeys, ROUND_KEYS_SIZE);
		
		
		
		/* ============= Process the current Block ==================== */
		process_block(Delta_1, Delta_2, result, blk, W, 1, Is_Final, ENCRYPT, AD, roundkeysb);
		//memcpy(tab0, result, 16);
		//if(i ==0)
		
		//tab0[0]= Is_Final;
			
		/* === Compute the next Block and updating the pointers and counters ===*/
		if(adlen==0) break; 
		
		else if(adlen <= 16) {
			//uint8_t adlenb = 16 -adlen;
			load_block_AD(blk, ad, ozs, adlen); 
			//memcpy(tab0, blk, 16);
			//tab0[2]= adlen;
			if(adlen != 16) Is_Final = 1;
			adlen = 0; 
		}

		else {load_block(blk, ad, ozs, 16, 0); ad +=16; adlen -=16;}
		
		i++;
		//free(roundkeysb);
	}
	
}

/* ------------------------------------ */

int crypto_aead_decrypt(
	uint8_t *m, int32_t *mlen,
	uint8_t *nsec,
	const uint8_t *c, int32_t clen,
	 uint8_t *ad, int32_t adlen,
	const uint8_t *npub,
	uint8_t *k, uint8_t *roundKeys
	)
{
    uint8_t param[]={0,0,0,0,0,0,0,0}; 
	
	block L, W, Delta_0, Delta_1, Delta_2, blk, result, CS;
	uint8_t i;
	for(i=0; i<16; i++) W[i] = 0; 
	uint8_t zeroes[16], Is_Final = 0;

	for(i=0; i<16; i++)	{
		zeroes[i]=0x00;
	}   		// all zero.
	
	
	if(clen < 16)
		return -1;

	*mlen = clen - 16; 
	
	
	
	/* =========== Generate the Masks ========== */
	AES(ENCRYPT, L, zeroes, roundKeys);
	mult_3(Delta_0, L); 
	mult_inv2(Delta_0, Delta_0); 
	
	copy_block(Delta_1, L);
	//mult_inv2(Delta_1, L); 	

	mult_3(Delta_2, L); 
	mult_3(Delta_2, Delta_2); 
	//mult_inv2(Delta_2, Delta_2);

	
	/* =============  Process Associated Data  ================ */
	for(i=0; i<16; i++)
		W[i]=0x00;
		
	//for(i=0; i<adlen; i++) ad[i]= 0x00;
	process_AD(W, Delta_0, npub, param, ad, adlen, roundKeys); 
	Is_Final = 0;
	
	 load_block(CS, zeroes, zeroes, 16, 0);
	 
	 //memcpy(tab0, W, 16);

	 /* ================ Process Ciphertext Blocks ============ */
	 load_block(blk, c, zeroes, 16, 0);  

	 /* =================== Process 1st Block =================== */
	uint8_t *roundkeysb;
	roundkeysb = (uint8_t *) malloc(ROUND_KEYS_SIZE * sizeof(uint8_t) );
	
	memcpy(roundkeysb, roundKeys, ROUND_KEYS_SIZE);
	
	 if(clen<32){
	 	process_block(Delta_2, Delta_1, result, blk, W, 0, 1, DECRYPT, CIPHERTEXT, roundkeysb); 
		store_bytes(m, result, 0, clen-17); m += clen - 16;
	 }
	 else {
		if(clen == 32) 
			Is_Final = 1;
		
		process_block(Delta_2, Delta_1, result, blk, W, 1, Is_Final, DECRYPT,  CIPHERTEXT, roundkeysb);
		store_bytes(m, result, 0, 15);  m +=16;
	 }
	 xor_block(CS, CS, result); //store_bytes(nsec, result, 0, 7); 
	 clen -= 16; c+=16;

	 if(clen < 16){ 
		if(result[clen] != 0x80) return -1; 
		for(i=clen+1; i<16; i++) {if(result[i]!=0) return -1;} 
	 }
	 
	 
	//memcpy(m, tab0, 16);
	
	free(roundkeysb);
	/* ============= Process Successive Ciphertext Blocks ============== */
	while(clen > 16){
	   
	   load_block(blk, c, zeroes, 16, 0);  
	   
	   uint8_t *roundkeysd;
		roundkeysd = (uint8_t *) malloc(ROUND_KEYS_SIZE * sizeof(uint8_t) );
	
		memcpy(roundkeysd, roundKeys, ROUND_KEYS_SIZE);
		
	   if(clen < 32){ 
	   	process_block(Delta_2, Delta_1, result, blk, W, 0, 1, DECRYPT,  CIPHERTEXT, roundkeysd); 
		xor_block(result, result, CS);
	   	store_bytes(m, result, 0, clen - 17);  
	   }
	   else{ 
		if(clen == 32)
			Is_Final = 1;
	        process_block(Delta_2, Delta_1, result, blk, W, 1, Is_Final, DECRYPT,  CIPHERTEXT, roundkeysd); 
		if(clen == 32) {xor_block(result, result, CS);}
		store_bytes(m, result, 0, 15); 
	   } 
		
		free(roundkeysd);
		
	   xor_block(CS, CS, result);
	   clen -= 16; c+=16;

	   
	   if(clen < 16){ 
		if(result[clen] != 0x80) return -1; 
		for(i=clen+1; i<16; i++) {if(result[i]!=0) return -1;} 
	   }
	   else
		   m +=16; 
	}

	/* ==========  Process checksum block  ============= */
	uint8_t *roundkeysc;
	roundkeysc = (uint8_t *) malloc(ROUND_KEYS_SIZE * sizeof(uint8_t) );
	
	memcpy(roundkeysc, roundKeys, ROUND_KEYS_SIZE);
	
	process_block(Delta_1, Delta_2, result, CS, W, 1, 0, ENCRYPT, MESSAGE, roundkeysc); /* 2nd result was CS */
	
	free(roundkeysc);
	
	for(i=0; i<clen; i++) {if(result[i]!=c[i]) { return -1; }} 
	
	
	
	return 0;
}



uint8_t Decrypt(uint8_t *block, int32_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, int32_t  adlen, uint8_t *c, uint8_t *roundKeys)
{
	/* Add here the cipher decryption implementation */

		static uint8_t *nsec;
	nsec = malloc(CRYPTO_NSECBYTES);
	
	//length of inputs and param
	int32_t clen = mlen + CRYPTO_ABYTES;
	
	uint8_t *roundkeysb;
	roundkeysb = (uint8_t *) malloc(ROUND_KEYS_SIZE * sizeof(uint8_t) );
	
	memcpy(roundkeysb, roundKeys, ROUND_KEYS_SIZE);
	
	uint8_t adb[adlen];
	int32_t i;
	for(i=0; i<adlen; i++) {
		adb[i] = ad[i];
	}
	
	if(adlen !=16){
	return crypto_aead_decrypt(
	block, &mlen,
	nsec,
	c, clen,
	adb, adlen,
	npub,
	key, roundkeysb
	);}
	else if(adlen ==16){
	return crypto_aead_decrypt(
	block, &mlen,
	nsec,
	c, clen,
	adb, adlen,
	npub,
	key, roundkeysb
	);
	}
	
	free(roundkeysb);
	
}


