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



#define maj(x,y,z)     (  ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))  )
#define ch(x,y,z)      (  ((x) & (y)) ^ ( ((x) ^ 1) & (z))  )

//decrypt one bit
void Decrypt_StateUpdate128_1bit(uint8_t *state, uint8_t *plaintextbit, uint8_t ciphertextbit, uint8_t *ks, uint8_t ca, uint8_t cb)
{
    uint32_t  j;
    uint8_t f;

    state[289] ^= state[235] ^ state[230];
    state[230] ^= state[196] ^ state[193];
    state[193] ^= state[160] ^ state[154];
    state[154] ^= state[111] ^ state[107];
    state[107] ^= state[66]  ^ state[61];
    state[61]  ^= state[23]  ^ state[0];

    f = FBK128(state, ks, ca, cb);

    for (j = 0; j <= 291; j++) state[j] = state[j+1];
    *plaintextbit = *ks ^ ciphertextbit;
    state[292] = f ^ *plaintextbit;
}

// decrypt one byte
void acorn128_dec_onebyte(uint8_t *state, uint8_t *plaintextbyte,
       uint8_t ciphertextbyte, uint8_t *ksbyte, uint8_t cabyte, uint8_t cbbyte)
{
    uint8_t i;
    uint8_t plaintextbit,ciphertextbit, ks,ca,cb;

    *plaintextbyte = 0;
    for (i = 0; i < 8; i++)
    {
        ca = (cabyte >> i) & 1;
        cb = (cbbyte >> i) & 1;
        ciphertextbit = (ciphertextbyte >> i) & 1;
        Decrypt_StateUpdate128_1bit(state, &plaintextbit, ciphertextbit, &ks, ca, cb);
        *plaintextbyte |= (plaintextbit << i);
    }
}


/* ------------------------------------ */

int32_t crypto_aead_decrypt(
	uint8_t *m, int32_t *mlen,
	uint8_t *nsec,
	const uint8_t *c, int32_t clen,
	const uint8_t *ad, int32_t adlen,
	const uint8_t *npub,
	const uint8_t *k
	)
{
  int32_t i;
    uint8_t plaintextbyte, ciphertextbyte, ksbyte;
    uint8_t state[293];
    uint8_t tag[16];
    uint8_t check = 0;
    uint8_t ca, cb;

    if (clen < 16) return -1;

    //initialization stage
    acorn128_initialization(k, npub, state);

    //process the associated data
    for (i = 0; i < adlen; i++)
    {
        acorn128_enc_onebyte(state, ad[i], &ciphertextbyte, &ksbyte, 0xff, 0xff);
    }

    for (i = 0; i < 256/8; i++)
    {
        if ( i == 0 ) plaintextbyte = 0x1;
        else plaintextbyte = 0;

        if ( i < 128/8)   ca = 0xff;
        else ca = 0;

        cb = 0xff;

        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, ca, cb);
    }

    //process the ciphertext
    *mlen = clen - 16;

    for (i = 0; i < *mlen; i++)
    {
        acorn128_dec_onebyte(state, &m[i], c[i], &ksbyte, 0xff, 0);
    }

    for (i = 0; i < 256/8; i++)
    {
        if ( i == 0 ) plaintextbyte = 0x1;
        else plaintextbyte = 0;

        if ( i < 128/8)   ca = 0xff;
        else ca = 0;

        cb = 0;

        acorn128_enc_onebyte(state, plaintextbyte, &ciphertextbyte, &ksbyte, ca, cb);
    }

    //finalization stage, we assume that the tag length is a multiple of bytes
    acorn128_tag_generation(*mlen, adlen, 16, tag, state);

    for (i = 0; i  < 16; i++) check |= (tag[i] ^ c[clen - 16 + i]);
    if (check == 0) return 0;
    else return -1;
}



uint8_t Decrypt(uint8_t *block, int32_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, int32_t  adlen, uint8_t *c, uint8_t *roundKeys)
{
	/* Add here the cipher decryption implementation */

		static uint8_t *nsec;
	nsec = malloc(CRYPTO_NSECBYTES);
	
	//length of inputs and param
	int32_t clen = mlen + CRYPTO_ABYTES;
	
	uint8_t *AD;
    AD = (uint8_t *) malloc(adlen * sizeof(uint8_t) );
    memcpy(AD, ad, adlen);
	
	if(adlen !=16){
	return crypto_aead_decrypt(
	block, &mlen,
	nsec,
	c, clen,
	AD, adlen,
	npub,
	key
	);}
	else if(adlen ==16){
	return crypto_aead_decrypt(
	block, &mlen,
	nsec,
	c, clen,
	AD, adlen,
	npub,
	key
	);
	}
	
}


