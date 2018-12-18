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



void from8To4Bits(uint8_t *tab4, const uint8_t *tab8){
	uint8_t compt, i;
	compt = 0;
	for(i=0; i<8; i++){
		tab4[compt] = tab8[i] >>4;
		compt++;
		tab4[compt] = tab8[i] & 0x0f;
		compt++;
	}
}

void from4To8Bits(uint8_t *tab8, const uint8_t *tab4){
	uint8_t compt, i;
	compt = 0;
	for(i=0; i<8; i++){
		tab8[i] = tab4[compt] <<4;
		compt++;
		tab8[i] |= tab4[compt];
		compt++;
	}
}

void permutation(uint8_t *tab){
	uint8_t tmp[8];
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

/* Lilliput AE */
void subkey(const uint8_t key[KEY_SIZE], const uint8_t tweak[TWEAK_SIZE], uint8_t *roundkeys){
	uint8_t TK1[16];
	uint8_t TK2[16];
	
	from8To4Bits(TK1, key);
	from8To4Bits(TK2, tweak);
	
	int16_t i, j;
	for(i=0; i<29; i++){
		/*Extract RK */
		
		for(j=0; j<8; j++){
			roundkeys[j+ i*8] = TK1[j] ^ TK2[j] ;
		}
		
		/* State Tweakey update - Permutation + LSFR */
		permutation(TK1);
		permutation(TK2);
		
		for(j = 0 ; j < 8 ; j++){
			TK2[j] = (TK2[j] <<1 | ((TK2[j] >>3)^((TK2[j] & 0x04) >>2)) ) & 0x0f;
		}
		
	}
	
	for(j=0; j<8; j++){
		roundkeys[j+ i*8] = TK1[j] ^ TK2[j] ;
	}
}

/* ENCRYPT Lilliput (from v04 in FELICS) */
void EncryptLILLIPUT(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i;
	uint8_t tmpblock[16];
	from8To4Bits(tmpblock, block);	
	
  /*29 rounds */
  for(i = 0 ; i < 29 ; i++)
  {
    uint8_t tmproundKeysi[8];

  	memcpy(tmproundKeysi, roundKeys + i*8, 8);
    
    /* NonLinearLayer + LinearLayer */
    
    tmpblock[8]  ^= ( READ_SBOX_BYTE(S[tmpblock[7] ^     tmproundKeysi[ 0]])) ;
    tmpblock[9]  ^= ( READ_SBOX_BYTE(S[tmpblock[6] ^     tmproundKeysi[ 1]]) ^ tmpblock[7]);
    tmpblock[10] ^=  (READ_SBOX_BYTE(S[tmpblock[5] ^     tmproundKeysi[ 2]]) ^ tmpblock[7]);
    tmpblock[11] ^=  (READ_SBOX_BYTE(S[tmpblock[4] ^     tmproundKeysi[ 3]]) ^ tmpblock[7]);
    tmpblock[12] ^= ( READ_SBOX_BYTE(S[tmpblock[3] ^     tmproundKeysi[ 4]]) ^ tmpblock[7]);
    tmpblock[13] ^= ( READ_SBOX_BYTE(S[tmpblock[2] ^     tmproundKeysi[ 5]]) ^ tmpblock[7]);
    tmpblock[14] ^= ( READ_SBOX_BYTE(S[tmpblock[1] ^     tmproundKeysi[ 6]]) ^ tmpblock[7]);
    tmpblock[15] ^= ( READ_SBOX_BYTE(S[tmpblock[0] ^     tmproundKeysi[ 7]]) ^ tmpblock[7] ^ tmpblock[6] ^ tmpblock[5] ^ tmpblock[4] ^ tmpblock[3] ^ tmpblock[2] ^ tmpblock[1]);
    
    
    /* PermutationLayer */

    /*Avoid useless operation in the for loops and create as many temp as necessary, use all the temp at the end */
    uint8_t temp13 = tmpblock[13];
	tmpblock[13] = tmpblock[0];
	uint8_t temp9 = tmpblock[9];
	tmpblock[9] = tmpblock[1];
	uint8_t temp14 = tmpblock[14];
	tmpblock[14] = tmpblock[2];
	uint8_t temp8 = tmpblock[8];
	tmpblock[8] = tmpblock[3];
	uint8_t temp10 = tmpblock[10];
	tmpblock[10] = tmpblock[4];
	uint8_t temp11 = tmpblock[11];
	tmpblock[11] = tmpblock[5];
	uint8_t temp12 = tmpblock[12];
	tmpblock[12] = tmpblock[6];
	uint8_t temp15 = tmpblock[15];
	tmpblock[15] = tmpblock[7];
	
	tmpblock[4] = temp8;
	tmpblock[5] = temp9;
	tmpblock[3] = temp10;
	tmpblock[1] = temp11;
	tmpblock[2] = temp12;
	tmpblock[6] = temp13;
	tmpblock[0] = temp14;
	tmpblock[7] = temp15;
	
  } /* end round */
  
  uint8_t tmproundKeysi[8];
  memcpy(tmproundKeysi, roundKeys + i*8, 8);
  
  /* last round */
    
	tmpblock[8]  ^= ( READ_SBOX_BYTE(S[tmpblock[7] ^     tmproundKeysi[ 0]])) ;
    tmpblock[9]  ^= ( READ_SBOX_BYTE(S[tmpblock[6] ^     tmproundKeysi[ 1]]) ^ tmpblock[7]);
    tmpblock[10] ^=  (READ_SBOX_BYTE(S[tmpblock[5] ^     tmproundKeysi[ 2]]) ^ tmpblock[7]);
    tmpblock[11] ^=  (READ_SBOX_BYTE(S[tmpblock[4] ^     tmproundKeysi[ 3]]) ^ tmpblock[7]);
    tmpblock[12] ^= ( READ_SBOX_BYTE(S[tmpblock[3] ^     tmproundKeysi[ 4]]) ^ tmpblock[7]);
    tmpblock[13] ^= ( READ_SBOX_BYTE(S[tmpblock[2] ^     tmproundKeysi[ 5]]) ^ tmpblock[7]);
    tmpblock[14] ^= ( READ_SBOX_BYTE(S[tmpblock[1] ^     tmproundKeysi[ 6]]) ^ tmpblock[7]);
    tmpblock[15] ^= ( READ_SBOX_BYTE(S[tmpblock[0] ^     tmproundKeysi[ 7]]) ^ tmpblock[7] ^ tmpblock[6] ^ tmpblock[5] ^ tmpblock[4] ^ tmpblock[3] ^ tmpblock[2] ^ tmpblock[1]);
    
   from4To8Bits(block, tmpblock);
	
}




/*------------------------------ */
/* OCB3 */
void xor_block(uint8_t *d, const uint8_t *s1, const uint8_t *s2) {
    int8_t i;
    for (i=0; i<8; i++)
        d[i] = s1[i] ^ s2[i];
}
	

void EncryptBLOCK(uint8_t *block, const uint8_t *key, const uint8_t *tweak){
	uint8_t roundkeys[ROUND_KEYS_SIZE];
	
	subkey(key, tweak, roundkeys);
	EncryptLILLIPUT(block, roundkeys);
}

void offset_tweak(uint8_t *tweak, const uint8_t value) {
    tweak[0]=(tweak[0] & 0xf) ^ (value<<4) ;
} 
   
void update_tweak(uint8_t *tweak, const uint8_t value, const uint32_t counter) {
    tweak[0]=(tweak[0] & 0xf) ^ (value<<4) ;
    
    tweak[4] = (tweak[4]&0xf0) ^ ((counter >> 24ULL) & 0xf);
    tweak[5] = ((counter >> 16ULL) & 0xff);
    tweak[6] = ((counter >> 8ULL) & 0xff);
    tweak[7] = ((counter >> 0ULL) & 0xff);
       
}

void uptdate_tag_in_tweak(uint8_t *temp_tweak, const uint8_t *tweak, const uint32_t counter) {
    temp_tweak[4] = tweak[4] ^ ((counter>>24) & 0xff );
    temp_tweak[5] = tweak[5] ^ ((counter>>16) & 0xff );
    temp_tweak[6] = tweak[6] ^ ((counter>> 8) & 0xff );
    temp_tweak[7] = tweak[7] ^ ((counter>> 0) & 0xff );
    
}

/* ------------------------------------------------------------------------- */

int8_t ocb_encrypt( uint8_t *c, const uint8_t *key, const uint8_t *n,
                     const uint8_t *ad, uint32_t adlen,
                     const uint8_t *m, uint32_t mlen) {
	uint32_t i, j;
	
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
	
	/* Tag Generation */
	memset(tweak, 0, TWEAK_SIZE);
	
	for(i=1; i<=mlen/8; i++, m=m+8){
		uint8_t tmp[8];
		memcpy(tmp, m, 8);
		update_tweak(tweak, 0x0, i-1);
		EncryptBLOCK(tmp, key, tweak);
		
		xor_block(auth, auth, tmp);
	}
	
	remain = mlen%8;
	if (remain > 0) {
		uint8_t tmp[8];
		memset(tmp, 0, 8);
		memcpy(tmp, m, remain);
		tmp[remain] = 0x80;
		
		update_tweak(tweak, 0x4, i-1);
		EncryptBLOCK(tmp, key, tweak);
		xor_block(auth, auth, tmp);
		
		m = m +remain;
	}
	
	m = m - mlen; 
		
	memcpy(tag, auth, 8);
	memset(tweak, 0, TWEAK_SIZE);
	offset_tweak(tweak, 0x1);
	memcpy( tweak + 1, n, 7);
	EncryptBLOCK(tag, key, tweak); /* tag generated */
	
	/* Encrypt */
	uint8_t encr[8]; /* 00000000||n */
	memset(encr, 0, 8);
	memcpy( encr + 1, n, 7);
	
	memset(tweak, 0, TWEAK_SIZE);
	memcpy(tweak, tag, CRYPTO_ABYTES );
    tweak[0] = 0x80 ^ (tweak[0] & 0x7f);
    
    uint8_t temp_tweak[16];
    memcpy( temp_tweak, tweak, 16 );
    	
	/* begin encryption */
	for(i=1; i<=mlen/8; i++, m=m+8, c=c+8){
		uint8_t tmp[8];
		memcpy(tmp, encr, 8);
		uptdate_tag_in_tweak(temp_tweak, tweak, i-1);
		EncryptBLOCK(tmp, key, temp_tweak);
		
		xor_block(c, m, tmp);
		
	}
	
	
	remain = mlen%8;
	if(remain > 0){
		uint8_t tmp[8];
		memcpy(tmp, encr, 8);	
		uptdate_tag_in_tweak(temp_tweak, tweak, i-1);
		EncryptBLOCK(tmp, key, temp_tweak);
		
		for(j=0; j<remain; j++){
			c[j] = m[j] ^ tmp[j];
		}
		
		c = c +remain;
		m = m +remain;
	}
	
	
	memcpy(c, tag, CRYPTO_ABYTES);
	
	return 0;
}


/* ------------------------------------------------------------------------- */

uint8_t crypto_aead_encrypt(
	uint8_t *c, uint32_t *clen,
	const uint8_t *m, uint32_t mlen,
	const uint8_t *ad, uint32_t adlen,
	const uint8_t *nsec,
	const uint8_t *npub,
	uint8_t *k, uint8_t *roundKeys
)
{
	*clen = mlen + TAGBYTES;
	
    ocb_encrypt(c, k, npub, ad,
            adlen, m, mlen);
    return 0;
}

/*--------------------------------*/

void Encrypt(uint8_t *block, int32_t  mlen, uint8_t *key, uint8_t *npub,
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
	crypto_aead_encrypt(
	c, &clen,
	block, (uint32_t)mlen,
	adb, (uint32_t)adlen,
	nsec,
	npub,
	key, roundKeys
	);}
	else if(adlen ==16){
	crypto_aead_encrypt(
	c, &clen,
	block, (uint32_t)mlen,
	adb, (uint32_t)adlen,
	nsec,
	npub,
	key, roundKeys
	);
	}
	
	free(adb);
	
}



