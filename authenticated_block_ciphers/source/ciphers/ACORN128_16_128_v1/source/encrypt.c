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


/* -------------------------- */

#define maj(x,y,z)     (  ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))  )
#define ch(x,y,z)      (  ((x) & (y)) ^ ( ((x) ^ 1) & (z))  )

uint8_t KSG128(uint8_t *state)
{
    return ( state[12] ^ state[154] ^ maj(state[235], state[61], state[193]) ^ ch(state[230], state[111], state[66]) );
}

uint8_t mem;
uint8_t FBK128(uint8_t *state, uint8_t *ks, uint8_t ca, uint8_t cb)
{
    uint8_t f;
    *ks = KSG128(state);
    f  = state[0] ^ (state[107] ^ 1) ^ maj(state[244], state[23], state[160]) ^ (ca & state[196]) ^ (cb & (*ks));
    
    return f;
}

//encrypt one bit
void Encrypt_StateUpdate128_1bit00(uint8_t *state, uint8_t plaintextbit, uint8_t *ciphertextbit, uint8_t *ks, uint8_t cb)
{
    uint32_t  j;
    uint8_t f;
	uint8_t ca = 0x00;
	
    state[289] ^= state[235] ^ state[230];
    state[230] ^= state[196] ^ state[193];
    state[193] ^= state[160] ^ state[154];
    state[154] ^= state[111] ^ state[107];
    state[107] ^= state[66]  ^ state[61];
    state[61]  ^= state[23]  ^ state[0];
    
	//mem= ca;
    f  = FBK128(state, ks, ca, cb);

    for (j = 0; j <= 291; j++) state[j] = state[j+1];
    state[292] = f ^ plaintextbit;
    *ciphertextbit = *ks ^ plaintextbit;
}

void Encrypt_StateUpdate128_1bit(uint8_t *state, uint8_t plaintextbit, uint8_t *ciphertextbit, uint8_t *ks, uint8_t ca, uint8_t cb)
{
    uint32_t  j;
    uint8_t f;
	//uint8_t ca = 0xff;
	
    state[289] ^= state[235] ^ state[230];
    state[230] ^= state[196] ^ state[193];
    state[193] ^= state[160] ^ state[154];
    state[154] ^= state[111] ^ state[107];
    state[107] ^= state[66]  ^ state[61];
    state[61]  ^= state[23]  ^ state[0];
    
	//mem= ca;
    f  = FBK128(state, ks, ca, cb);

    for (j = 0; j <= 291; j++) state[j] = state[j+1];
    state[292] = f ^ plaintextbit;
    *ciphertextbit = *ks ^ plaintextbit;
}

// encrypt one byte
void acorn128_enc_onebyte(uint8_t *state, uint8_t plaintextbyte,
       uint8_t *ciphertextbyte, uint8_t *ksbyte, uint8_t cabyte, uint8_t cbbyte)
{
    uint8_t i;
    uint8_t plaintextbit,ciphertextbit,kstem,ca,cb;

    *ciphertextbyte = 0;
    kstem = 0;
    *ksbyte = 0;
    for (i = 0; i < 8; i++)
    {
        ca = (cabyte >> i) & 1;
        cb = (cbbyte >> i) & 1;
        plaintextbit = (plaintextbyte >> i) & 1;
        
        if(ca==0x00){
        	Encrypt_StateUpdate128_1bit00(state, plaintextbit, &ciphertextbit, &kstem, cb);
        }
        else{
        	Encrypt_StateUpdate128_1bit(state, plaintextbit, &ciphertextbit, &kstem, ca, cb);
        }
        *ciphertextbyte |= (ciphertextbit << i);
        *ksbyte |= (kstem << i);
    }
    
    
}


//The initialization state of ACORN
/*The input to initialization is the 128-bit key; 128-bit IV;*/
void acorn128_initialization(const uint8_t *key, const uint8_t *iv, uint8_t *state)
{
        int32_t i,j;
        uint8_t m[293], ks, tem;

        //initialize the state to 0
        for (j = 0; j <= 292; j++) state[j] = 0;

        //set the value of m
        for (j = 0; j <=  15;   j++)   m[j] = key[j];
        for (j = 16; j <= 31;   j++)   m[j] = iv[j - 16];
        for (j = 32; j <= 223;  j++)   m[j] = key[j & 0xf];
        m[32] ^= 1;

        //run the cipher for 1792 steps
        for (i = 0; i < 224; i++)
        {
             acorn128_enc_onebyte(state, m[i], &tem, &ks, 0xff, 0xff);
        }
}

//the finalization state of acorn
void acorn128_tag_generation(int32_t msglen, int32_t adlen, uint8_t maclen, uint8_t *mac, uint8_t *state)
{
    int32_t i;
    uint8_t plaintextbyte  = 0;
    uint8_t ciphertextbyte = 0;
    uint8_t ksbyte = 0;

    for (i = 0; i < 768/8; i++)
    {
        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, 0xff, 0xff);
        if ( i >= (768/8 - 16) ) {mac[i-(768/8-16)] = ksbyte; }
    }
}


/*------------------------------*/

int32_t crypto_aead_encrypt(
	uint8_t *c, int32_t *clen,
	const uint8_t *m, int32_t mlen,
	 uint8_t *ad, int32_t adlen,
	const uint8_t *nsec,
	const uint8_t *npub,
	uint8_t *k
	)
{
  	int32_t i;
    uint8_t plaintextbyte, ciphertextbyte, ksbyte, mac[16];
    uint8_t state[293];
    uint8_t ca, cb;
    
    

    //initialization stage
    acorn128_initialization(k, npub, state);

    //process the associated data
    for (i = 0; i < adlen; i++)
    {
    	//ad[i] = 0x00;
        acorn128_enc_onebyte(state, ad[i], &ciphertextbyte, &ksbyte, 0xff, 0xff);
    }

    for (i = 0; i < 32; i++)
    {
        if ( i == 0 ) plaintextbyte = 0x1;
        else plaintextbyte = 0;

        if ( i < 16)   ca = 0xff;
        else ca = 0;

        cb = 0xff;

        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, ca, cb);
    }


    //process the plaintext
    for (i = 0; i < mlen; i++)
    {
        acorn128_enc_onebyte(state, m[i], &(c[i]), &ksbyte, 0xff, 0 );
    }

    for (i = 0; i < 32; i++)
    {
        if (i == 0) plaintextbyte = 0x1;
        else plaintextbyte = 0;

        if ( i < 16)   ca = 0xff;
        else ca = 0;

        cb = 0;

        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, ca, cb);
    }

    //finalization stage, we assume that the tag length is a multiple of bytes
    acorn128_tag_generation(mlen, adlen, 16, mac, state);

    *clen = mlen + 16;
    memcpy(c+mlen, mac, 16);

	
    return 0;
}


/*--------------------------------*/

void Encrypt(uint8_t *block, int32_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, int32_t  adlen, uint8_t *c, uint8_t *roundKeys)
{

	static uint8_t *nsec;
	nsec = malloc(CRYPTO_NSECBYTES);
	
	//length of inputs and param
	int32_t clen = mlen + CRYPTO_ABYTES;
	
	uint8_t *AD;
    AD = (uint8_t *) malloc(adlen * sizeof(uint8_t) );
    memcpy(AD, ad, adlen);
	
	if(adlen !=16){
	crypto_aead_encrypt(
	c, &clen,
	block, mlen,
	AD, adlen,
	nsec,
	npub,
	key
	);}
	else if(adlen ==16){
	crypto_aead_encrypt(
	c, &clen,
	block, mlen,
	AD, adlen,
	nsec,
	npub,
	key
	);
	}
	
}



