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


static int crypto_aead_encrypt(
	uint8_t *c, size_t *clen,
	const uint8_t *m, size_t mlen,
	const uint8_t *ad, size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
	)
{
        size_t i;
        RAM_DATA_BYTE plaintextblock[16], ciphertextblock[16], mac[16];
        RAM_DATA_BYTE aegis128_state[80];

        //initialization stage
        aegis128_initialization(k, npub, aegis128_state);

        //process the associated data
        for (i = 0; (i+16) <= adlen; i += 16) {
              aegis128_enc_aut_step(ad+i, ciphertextblock, aegis128_state);
        }

        //deal with the partial block of associated data
        //in this program, we assume that the message length is multiple of bytes.
        if (  (adlen & 0xf) != 0 )  {
              memset(plaintextblock, 0, 16);
              memcpy(plaintextblock, ad+i, adlen & 0xf);
              aegis128_enc_aut_step(plaintextblock, ciphertextblock, aegis128_state);
        }


        //encrypt the plaintext
        for (i = 0; (i+16) <= mlen; i += 16) {
              aegis128_enc_aut_step(m+i, c+i, aegis128_state);
        }

        // Deal with the partial block
        // In this program, we assume that the message length is multiple of bytes.
        if (  (mlen & 0xf) != 0 )  {
              memset(plaintextblock, 0, 16);
              memcpy(plaintextblock, m+i, mlen & 0xf);
              aegis128_enc_aut_step(plaintextblock, ciphertextblock, aegis128_state);
              memcpy(c+i,ciphertextblock, mlen & 0xf);
        }

        //finalization stage, we assume that the tag length is a multiple of bytes
        aegis128_tag_generation(mlen, adlen, 16, mac, aegis128_state);
        *clen = mlen + 16;
        memcpy(c+mlen, mac, 16);
		
        return 0;
}


/*--------------------------------*/

void Encrypt(uint8_t *block, size_t mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t adlen, uint8_t *c)
{
	//length of inputs and param
	size_t clen;
    crypto_aead_encrypt(c, &clen, block, mlen, ad, adlen, npub, key);
}
