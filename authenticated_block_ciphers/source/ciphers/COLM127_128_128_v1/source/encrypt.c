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

#define IT_GAP 127 // Denotes the no. of blocks after which intermediate tags are generated.


#define alpha_128 0x87 // Denotes the primitive polynomial x^128+x^7+x^2+x+1
#define AD 0
#define MESSAGE 1
#define CIPHERTEXT 2
#define ENCRYPT 1
#define DECRYPT 0
#define IT_MAX 32  // This denotes the maximum no. of intermediate tag blocks generated. It is required for  intermediated tag versions only.  We provide intermediate tags upto message length of 2^16 bytes. As we generate intermediate tags after 127 blocks, maximum floor(2^12/127) = 32 blocks of intermediate tags can be generated. So, corresponding ABYTES value will be 536 (= 2^4*32+24) for fixed versions using intermediate tags and 552 (= 2^4*32+40) for flexible version. 


typedef uint8_t block[16];


/* ========================= General Modules =============================== */

/* ===== Xor of two block =====*/
 void xor_block(block d, const block s1, const block s2) {int32_t i; for(i=0; i<16; i++) d[i] = s1[i] ^ s2[i];}

/* ===== Copy the content of one block to another ======= */
 void copy_block(block out, block in){int32_t i; for(i=0; i <16; i++) {out[i] = in[i];}}

/* ==== Implement Field multiplication by 2 in GF(2^128) using x^128+x^7+x^2+x+1 as primitive polynomial ==== */
 void mult_2(block b, block s) {int32_t i; block d; uint8_t temp = s[0]>>7;
   	for (i=0; i<15; i++)	{d[i] = (s[i] << 1) | (s[i+1] >> 7);}
 	d[15] = (s[15] << 1); if(temp==1){d[15] ^= alpha_128;} 
	copy_block(b,d);}

/*== Implement Field multiplication by 2^{-1} in GF(2^128) using x^128+x^7+x^2+x+1 as primitive polynomial ==*/
/*static void mult_inv2(block b, block s) {int32_t i; block d; uint8_t temp = s[15]&1;
   	for (i=1; i<16; i++)	{d[i] = (s[i-1] << 7) | (s[i] >> 1) ;}
   	d[0] = (s[0] >> 1); if(temp==1){d[15] ^= 0x43; d[0] ^= 0x80;}
	copy_block(b,d);}  */

/* ==== Implement Field multiplication by 3 in GF(2^128) using x^128+x^7+x^2+x+1 as primitive polynomial ==== */
 void mult_3(block d, block s){ block res; mult_2(res, s); xor_block(res, res, s); copy_block(d,res); }

/* ==== Implement Field multiplication by 7 in GF(2^128) using x^128+x^7+x^2+x+1 as primitive polynomial ==== */
 void mult_7(block d, block s){ block res; mult_2(res, s); mult_3(res, res); xor_block(res, res, s); copy_block(d,res); }

/* == Load len1 bits of a1, followed by len2 bits of a2 in the block L. If L is not full, use 10* padding ==*/
 void load_block(block L, const uint8_t *a1, const uint8_t *a2, uint8_t len1, uint8_t len2){
	uint8_t i; for(i=0; i<len1; i++)	{L[i] = a1[i];}	
	for(i=0; i<len2; i++)	{L[i+len1] = a2[i];}
	if(len1 + len2 < 16)	{L[len1+len2]=0x80; for(i=len2+len1+1; i<16; i++) L[i]=0x00;}  }

/* ===== Store the value of block in a character array ======= */
 void store_bytes(uint8_t *b, block Blk, uint8_t first, uint8_t last){
 uint8_t i; 
	for(i=first;i<=last;i++){
		b[i-first] = Blk[i];
	}
}


/* ======== Check equality of two blocks ========= */
/*int is_equal_block(block blk1, block blk2){
	int32_t i; 
	for(i=0; i<16; i++){
		if(blk1[i] != blk2[i]) return -1;
	} 
	return 0;
}*/



/* ===========  AES Key Scheduling for 10 rounds ============ */


 void AES(uint8_t Is_Encrypt, block out, block in, uint8_t *key){
	memcpy(out, in, BLOCK_SIZE);
	if(Is_Encrypt == ENCRYPT)
		EncryptAES(out, key);
	else
		DecryptAES(out, key);
} 


/* ========================== Modules Specific to ELmD ================================== */


/* ==== Updates mask Delta (depending on completeness of block) and mask the block ===== */
 void mask(block Delta, block XX, const block X, uint8_t Is_Complete, uint8_t Is_Final){	
	if(Is_Final == 1){
		mult_7(Delta, Delta); 
		if(Is_Complete == 0) { mult_7(Delta, Delta);}
	}
	else 			{mult_2(Delta, Delta);} 		
	xor_block(XX, X, Delta);}


/* ====  Linear Mix Operation for Encryption/Decryption and Final/Non-final blocks ===== */ 
 void linear_mix(block W, block Y, block X, uint8_t Is_Encrypt){
	block w_2, w_3; mult_3(w_3, W); mult_2(w_2, W); 	
	xor_block(Y, X, w_3);
	if(Is_Encrypt == ENCRYPT)	{xor_block(W, X, w_2);}
	else if(Is_Encrypt == DECRYPT)	{xor_block(W, X, W);}
	
}


/* === Process a block : Mask --> Block Cipher Encrypt --> Linear Mix --> Block Cipher Decrypt --> Mask === */
/* =======  For AD process block, the Block cipher Decrypt and final Mask operations are not needed. ====== */
 void process_block(
	block Delta_1, block Delta_2, 
	block result, const block in_blk, block W,
	uint8_t Is_complete, uint8_t Is_Final, uint8_t Is_Encrypt,  uint8_t type_block, uint8_t *roundKeys) {

	block YY, XX, Y, X; 
	uint8_t i;
	for(i=0; i<16; i++) Y[i] = 0;
	for(i=0; i<16; i++) XX[i] = 0;
	
	//memcpy(tab0, Delta_1, 16);
	
	/* ==============   Mask  ================= */
	//if(type_block == AD || type_block == MESSAGE)
		mask(Delta_1, XX, in_blk, Is_complete, Is_Final);	
	//else
		//mask(Delta_1, XX, in_blk, Is_complete, Is_Final);	

	/* ==============  AES Enc/Dec =============== */
	if(type_block == AD)  { AES(ENCRYPT, X, XX, roundKeys); } 
	if(type_block == MESSAGE) { AES(ENCRYPT, X, XX, roundKeys); }				
	if(type_block == CIPHERTEXT){  AES(DECRYPT, X, XX, roundKeys); } 
	
	/* ============= Linear Mixing =============== */
	if(type_block == AD) 
		xor_block(W,W,X);
	else 
		linear_mix(W, Y, X, Is_Encrypt); // add xor mixing for ad
	
	/* ============= AES Enc/Dec ================== */
	if(type_block == MESSAGE) {  AES(ENCRYPT, YY, Y, roundKeys); }   
	if(type_block == CIPHERTEXT){  AES(DECRYPT, YY, Y, roundKeys); }
	
	/* =============== Mask ======================= */
	//if(type_block == MESSAGE)
		mask(Delta_2, result, YY, Is_complete, Is_Final);	
	//if(type_block == CIPHERTEXT)
		//mask(Delta_2, result, YY, Is_complete, Is_Final);

}



/* -------------------------- */

static void process_AD(
	block W, block Delta_1, const block npub, block param, 
	const uint8_t *ad, int16_t adlen, uint8_t *roundKeys) {	

	block Delta_2, blk, result;
	uint8_t Is_Final=0, ozs[16];
	uint8_t i; for(i=1; i<16; i++){ozs[i]=0x00;} ozs[0] = 0x80; 

	/* ===== make the first block blk based on npub and param ===== */
	load_block(blk, npub, param, 8, 8);
	
	while(1){ 
		uint8_t roundkeysb[ROUND_KEYS_SIZE];
		memcpy(roundkeysb, roundKeys, ROUND_KEYS_SIZE);
		
		/* ============= Process the current Block ==================== */
		process_block(Delta_1, Delta_2, result, blk, W, 1, Is_Final, ENCRYPT, AD, roundkeysb);
		
		/* === Compute the next Block and updating the pointers and counters ===*/
		if(adlen==0) break; 
		
		else if(adlen <= 16) {
			load_block(blk, ad, ozs, adlen, 16-adlen); 
			if(adlen != 16) Is_Final = 1;
			adlen = 0; 
		}

		else {load_block(blk, ad, ozs, 16, 0); ad +=16; adlen -=16;}
	}

}

/* ===================   COLM_0 Authenticated Encryption Function =================== */

uint8_t crypto_aead_encrypt(
	uint8_t *c, int32_t *clen,
	const uint8_t *m, int16_t mlen,
	 uint8_t *ad, int16_t adlen,
	const uint8_t *nsec,
	const uint8_t *npub,
	uint8_t *k, uint8_t *roundKeys
)
{
	uint8_t param[]={0,0x7f,0x80,0,0,0,0,0}; 
	
	block L, W, Delta_0, Delta_1, Delta_2, blk, result, CS;
	int16_t i; 
	uint8_t zeroes[16], ozs[16], blen = 16, Is_Final = 0, Is_complete =1;
	int32_t h, blk_ctr=0, blk_ctr1=0 ;
	for(i=0; i<16; i++)	{zeroes[i]=0x00;}   	
	for(i=1; i<16; i++)	{ozs[i]=0x00;} ozs[0] = 0x80; 	

	h = (mlen == 0) ? 0 : (mlen-1) / (IT_GAP * 16);
	
	if(h > IT_MAX)
		h = IT_MAX;

	*clen = mlen + 16 + h*16 ;  


	/* ==========  Generate the Masks =========== */
	AES(ENCRYPT, L, zeroes, roundKeys);
	mult_3(Delta_0, L); 
	copy_block(Delta_1, L);
	mult_3(Delta_2, L); 
	mult_3(Delta_2, Delta_2); 

	/* ======  Process Associated Data ======== */
	for(i=0; i<16; i++)
		W[i]=0x00;
	
	
		
	process_AD(W, Delta_0, npub, param, ad, adlen, roundKeys);
	Is_Final = 0;

	/* ================  Process Message Blocks ==================== */

	
	/* ====== Process the first Message block ============== */
	
	if(mlen < 16){ Is_complete = 0; }
	if(mlen <= 16) { blen = mlen; Is_Final = 1;}
	load_block(blk, m, ozs, blen, 0); copy_block(CS, blk); 
	
	uint8_t *roundkeysb;
	roundkeysb = (uint8_t *) malloc(ROUND_KEYS_SIZE * sizeof(uint8_t) );
	
	memcpy(roundkeysb, roundKeys, ROUND_KEYS_SIZE);
	
	//process_block(Delta_1, Delta_2, result, blk, W, Is_complete, Is_Final, ENCRYPT,  MESSAGE, roundkeysb);

	if(Is_complete == 1){
		if(Is_Final == 1){
			process_block(Delta_1, Delta_2, result, blk, W, 1, 1, ENCRYPT,  MESSAGE, roundkeysb);
		}
		else{
			process_block(Delta_1, Delta_2, result, blk, W, 1, 0, ENCRYPT,  MESSAGE, roundkeysb);
		}
	}
	else{
		if(Is_Final == 1){
			process_block(Delta_1, Delta_2, result, blk, W, 0, 1, ENCRYPT,  MESSAGE, roundkeysb);
		}
		else{
			process_block(Delta_1, Delta_2, result, blk, W, 0, 0, ENCRYPT,  MESSAGE, roundkeysb);
		}
	}

	store_bytes(c, result, 0, 15); c +=16; blk_ctr++; 
	if(mlen >= 16)  {mlen -= 16; m +=16;}
	else mlen = 0;
	
	free(roundkeysb);

	/* ============= Process Message blocks ================== */
	while(mlen > 0){
		if(mlen >= 16){
			load_block(blk, m, ozs, 16, 0); 
			if(mlen == 16){Is_Final = 1; xor_block(blk, CS, blk); }
			else xor_block(CS, CS, blk);
			//xor_block(CS, CS, blk); 
			blen = 16; mlen -= 16; m+=16; 
		}
		else 	{Is_complete = 0; Is_Final = 1; blen = mlen; mlen = 0; 
			load_block(blk, m, ozs, blen, 0); xor_block(blk, CS, blk);
			
		}	
		
		uint8_t *roundkeysd;
		roundkeysd = (uint8_t *) malloc(ROUND_KEYS_SIZE * sizeof(uint8_t) );
	
		memcpy(roundkeysd, roundKeys, ROUND_KEYS_SIZE);
		
		process_block(Delta_1, Delta_2, result, blk, W, Is_complete, Is_Final, ENCRYPT, MESSAGE, roundkeysd); 
		store_bytes(c, result, 0, 15); c +=16; blk_ctr++;
		
		if(blk_ctr == IT_GAP && blk_ctr1 < IT_MAX && mlen>0) {
			AES(ENCRYPT, result, W, roundkeysd); 	
			mask(Delta_2, result, result, 1,0); 
			store_bytes(c, result, 0, 15); c +=16; blk_ctr =0; blk_ctr1++;
		}
		
		free(roundkeysd);
	}

	/* ================ Process checksum block ====================== */
	uint8_t roundkeysc[ROUND_KEYS_SIZE];
	memcpy(roundkeysc, roundKeys, ROUND_KEYS_SIZE);
	
	
	process_block(Delta_1, Delta_2, result, blk, W, 1, 0, ENCRYPT, MESSAGE, roundkeysc); 
	store_bytes(c, result, 0, blen-1);
	//memcpy(tab0, Delta_2, 16);
	
	//memcpy(c, tab0, 16);

	return 0;
}

/*--------------------------------*/

void Encrypt(uint8_t *block, int32_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, int32_t  adlen, uint8_t *c, uint8_t *roundKeys)
{

	static uint8_t *nsec;
	nsec = malloc(CRYPTO_NSECBYTES);
	
	//length of inputs and param
	int16_t mlenb = (int16_t) mlen;
	int16_t adlenb = (int16_t) adlen;
	
	int32_t tag = ((int32_t) (mlen / 16)) ;
	tag = ((int32_t)(tag / 127)) * 128 ;
	int32_t clen = mlen + tag + adlen;
	
	uint8_t *adb;
    adb = (uint8_t *) malloc(adlen * sizeof(uint8_t) );
    memcpy(adb, ad, adlen);
    
	uint8_t *roundkeysb;
	roundkeysb = (uint8_t *) malloc(ROUND_KEYS_SIZE * sizeof(uint8_t) );
	
	memcpy(roundkeysb, roundKeys, ROUND_KEYS_SIZE);
	
	uint16_t i;
	for(i=0; i<clen; i++){
		c[i] = 0;
	}
	
	if(adlenb !=16){
	crypto_aead_encrypt(
	c, &clen,
	block, mlenb,
	adb, adlenb,
	nsec,
	npub,
	key, roundkeysb
	);}
	else if(adlenb ==16){
	crypto_aead_encrypt(
	c, &clen,
	block, mlenb,
	adb, adlenb,
	nsec,
	npub,
	key, roundkeysb
	);
	}
	
	free(roundkeysb);
	
}



