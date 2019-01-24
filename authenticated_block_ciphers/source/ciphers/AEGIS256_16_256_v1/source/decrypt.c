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
#include <stdlib.h>
#include <string.h>

#include "cipher.h"
#include "aegis_common.h"


//one step of decryption
 void aegis256_dec_aut_step(uint8_t *plaintextblk,
       const uint8_t *ciphertextblk, uint8_t *state)
{
   uint8_t tmp[16];

        AND128(plaintextblk, state+32, state+48);
        XOR128(plaintextblk, plaintextblk, state+16);
        XOR128(plaintextblk, plaintextblk, state+64);
        XOR128(plaintextblk, plaintextblk, state+80);
        XOR128(plaintextblk, plaintextblk, ciphertextblk);

        //state update function
        memcpy(tmp, state+80, 16);

        AESROUND(state+80, state+64, state+80);
        AESROUND(state+64, state+48, state+64);
        AESROUND(state+48, state+32, state+48);
        AESROUND(state+32, state+16, state+32);
        AESROUND(state+16, state+0,  state+16);
        AESROUND(state+0,  tmp,      state+0);

        //message is used to update the state.
        XOR128(state, state, plaintextblk);
}


/* ------------------------------------ */

int crypto_aead_decrypt(
	uint8_t *m, int32_t *mlen,
	uint8_t *nsec,
	const uint8_t *c, int32_t clen,
	const uint8_t *ad, int32_t adlen,
	const uint8_t *npub,
	const uint8_t *k
	)
{
		size_t i;
        uint8_t plaintextblock[16], ciphertextblock[16];
        uint8_t tag[16];
        uint8_t check = 0;
        uint8_t aegis256_state[96];

        if (clen < 16) return -1;

        aegis256_initialization(k, npub, aegis256_state);

        //process the associated data
        for (i = 0; (i+16) <= adlen; i += 16) {
              aegis256_enc_aut_step(ad+i, ciphertextblock, aegis256_state);
        }

        //deal with the partial block of associated data
        //in this program, we assume that the message length is multiple of bytes.
        if (  (adlen & 0xf) != 0 )  {
              memset(plaintextblock, 0, 16);
              memcpy(plaintextblock, ad+i, adlen & 0xf);
              aegis256_enc_aut_step(plaintextblock, ciphertextblock, aegis256_state);
        }

        *mlen = clen - 16;

        //decrypt the ciphertext
        for (i = 0; (i+16) <= *mlen; i += 16) {
              aegis256_dec_aut_step(m+i, c+i, aegis256_state);
        }

        // Deal with the partial block
        // In this program, we assume that the message length is multiple of bytes.
        if (  (*mlen & 0xf) != 0  )  {
              memset(ciphertextblock, 0, 16);
              memcpy(ciphertextblock, c+i, *mlen & 0xf);
              aegis256_dec_aut_step(plaintextblock, ciphertextblock, aegis256_state);
              memcpy(m+i, plaintextblock, *mlen & 0xf);

              //need to modify the state here (because in the last block, keystream is wrongly used to update the state)
              memset(plaintextblock, 0, *mlen & 0xf);
              ((uint64_t*)(void*)aegis256_state)[0] ^= ((uint64_t*)(void*)plaintextblock)[0];
              ((uint64_t*)(void*)aegis256_state)[1] ^= ((uint64_t*)(void*)plaintextblock)[1];
        }

        //we assume that the tag length is multiple of bytes
        aegis256_tag_generation(*mlen, adlen, 16, tag, aegis256_state);

        //verification
        for (i = 0; i  < 16; i++) check |= (tag[i] ^ c[clen - 16 + i]);
        if (check == 0) return 0;
        else return -1;
}



int Decrypt(uint8_t *block, size_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t  adlen, uint8_t *c, uint8_t *roundKeys)
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


