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
 static void aegis128L_dec_aut_step(uint8_t *plaintextblk,
       const uint8_t *ciphertextblk, uint8_t *state)
{
   uint8_t tmp[16];

    AND128(plaintextblk, state+32, state+48);
    XOR128(plaintextblk, plaintextblk, state+16);
    XOR128(plaintextblk, plaintextblk, state+96);
    XOR128(plaintextblk, plaintextblk, ciphertextblk);

    AND128(plaintextblk+16, state+96, state+112);
    XOR128(plaintextblk+16, plaintextblk+16, state+32);
    XOR128(plaintextblk+16, plaintextblk+16, state+80);
    XOR128(plaintextblk+16, plaintextblk+16, ciphertextblk+16);

    memcpy(tmp, state+112, 16);
    AESROUND(state+112,state+96, state+112);
    AESROUND(state+96, state+80, state+96);
    AESROUND(state+80, state+64, state+80);
    AESROUND(state+64, state+48, state+64);
    AESROUND(state+48, state+32, state+48);
    AESROUND(state+32, state+16, state+32);
    AESROUND(state+16, state+0,  state+16);
    AESROUND(state+0,  tmp,      state+0);

    //message is used to update the state.
    XOR128(state, state, plaintextblk);
    XOR128(state+64, state+64, plaintextblk+16);
}

static int crypto_aead_decrypt(
	uint8_t *m, size_t *mlen,
	const uint8_t *c, size_t clen,
	const uint8_t *ad, size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
	)
{
		unsigned int i;
		
        uint8_t plaintextblock[32], ciphertextblock[32];
        uint8_t tag[16];
        uint8_t check = 0;
        uint8_t aegis128L_state[128];

        if (clen < 16) return -1;

        aegis128L_initialization(k, npub, aegis128L_state);

        //process the associated data
        for (i = 0; (i+32) <= adlen; i += 32) {
              aegis128L_enc_aut_step(ad+i, ciphertextblock, aegis128L_state);
        }

        //deal with the partial block of associated data
        //in this program, we assume that the message length is multiple of bytes.
        if (  (adlen & 0x1f) != 0 )  {
              memset(plaintextblock, 0, 32);
              memcpy(plaintextblock, ad+i, adlen & 0x1f);
              aegis128L_enc_aut_step(plaintextblock, ciphertextblock, aegis128L_state);
        }

        *mlen = clen - 16;

        //decrypt the ciphertext
        for (i = 0; (i+32) <= *mlen; i += 32) {
              aegis128L_dec_aut_step(m+i, c+i, aegis128L_state);
        }

        // Deal with the partial block
        // In this program, we assume that the message length is multiple of bytes.
        if (  (*mlen & 0x1f) != 0  )  {
              memset(ciphertextblock, 0, 32);
              memcpy(ciphertextblock, c+i, *mlen & 0x1f);
              aegis128L_dec_aut_step(plaintextblock, ciphertextblock, aegis128L_state);
              memcpy(m+i, plaintextblock, *mlen & 0x1f);

              //need to modify the state here (because in the last block, keystream is wrongly used to update the state)
              memset(plaintextblock, 0, *mlen & 0x1f);
              XOR128(aegis128L_state, aegis128L_state, plaintextblock);
              XOR128(aegis128L_state+64, aegis128L_state+64, plaintextblock+16);
        }

        //we assume that the tag length is multiple of bytes
        aegis128L_tag_generation(*mlen, adlen, 16, tag, aegis128L_state);

        //verification
        for (i = 0; i  < 16; i++) check |= (tag[i] ^ c[clen - 16 + i]);
        if (check == 0) return 0;
        else return -1;
}

int Decrypt(uint8_t *block, size_t mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t adlen, uint8_t *c, uint8_t *roundKeys)
{
	//length of inputs and param
	size_t clen = mlen + CRYPTO_ABYTES;
    return crypto_aead_decrypt(block, &mlen, c, clen, ad, adlen, npub, key);
}


