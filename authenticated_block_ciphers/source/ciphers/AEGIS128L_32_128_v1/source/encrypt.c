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
#include "aegis_common.h""


// The initialization state of AEGIS
/*The input to initialization is the 128-bit key; 128-bit IV;*/
void aegis128L_initialization(const uint8_t *key, const uint8_t *iv, uint8_t *state)
{
        uint8_t i;
       uint8_t tmp[16];
       uint8_t constant[32] = {0x0,0x1,0x01,0x02,0x03,0x05,0x08,0x0d,0x15,0x22,0x37,0x59,0x90,0xe9,0x79,0x62,0xdb,0x3d,0x18,0x55,0x6d,0xc2,0x2f,0xf1,0x20,0x11,0x31,0x42,0x73,0xb5,0x28,0xdd};

       XOR128(state,  key,  iv);
       memcpy(state+16, constant+16, 16);
       memcpy(state+32, constant,    16);
       memcpy(state+48, constant+16, 16);
       XOR128(state+64, key, iv);
       XOR128(state+80, key, constant);
       XOR128(state+96, key, constant+16);
       XOR128(state+112,key, constant);

       for (i = 0; i < 10; i++)  {
             //state update function;
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
             XOR128(state, state, iv);
             XOR128(state+64, state+64, key);
       }
}


//the finalization state of AEGIS
void aegis128L_tag_generation(int32_t msglen, int32_t  adlen, uint8_t maclen, uint8_t *mac, uint8_t *state)
{
        uint8_t i;

        uint8_t tmp[16];
        uint8_t msgtmp[16];
        
        for(i = 0; i < 16; i++){
			msgtmp[i] = 0;
		}

        msgtmp[0] = adlen << 3;
        msgtmp[1] = msglen << 3;

        XOR128(msgtmp, msgtmp, state+32);

        for (i = 0; i < 7; i++) {
            //state update function
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
            XOR128(state,    state,    msgtmp);
            XOR128(state+64, state+64, msgtmp);
        }

        XOR128(state+96, state+96, state+80);
        XOR128(state+96, state+96, state+64);
        XOR128(state+96, state+96, state+48);
        XOR128(state+96, state+96, state+32);
        XOR128(state+96, state+96, state+16);
        XOR128(state+96, state+96, state+0);

        //in this program, the mac length is assumed to be multiple of bytes
        memcpy(mac,state+96,maclen);
}


// one step of encryption
 void aegis128L_enc_aut_step(const uint8_t *plaintextblk,
       uint8_t *ciphertextblk, uint8_t *state)
{
    uint8_t tmp[16];

    AND128(ciphertextblk, state+32, state+48);
    XOR128(ciphertextblk, ciphertextblk, state+16);
    XOR128(ciphertextblk, ciphertextblk, state+96);
    XOR128(ciphertextblk, ciphertextblk, plaintextblk);

    AND128(ciphertextblk+16, state+96, state+112);
    XOR128(ciphertextblk+16, ciphertextblk+16, state+32);
    XOR128(ciphertextblk+16, ciphertextblk+16, state+80);
    XOR128(ciphertextblk+16, ciphertextblk+16, plaintextblk+16);

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


/*------------------------------*/

static int crypto_aead_encrypt(
	uint8_t *c, size_t *clen,
	const uint8_t *m, size_t mlen,
	const uint8_t *ad, size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
	)
{
         uint32_t i;
        uint8_t plaintextblock[32], ciphertextblock[32], mac[16];
        uint8_t aegis128L_state[128];

        //initialization stage
        aegis128L_initialization(k, npub, aegis128L_state);


        //process the associated data
        for (i = 0; (i+32) <= (uint32_t)adlen; i += 32) {
              aegis128L_enc_aut_step(ad+i, ciphertextblock, aegis128L_state);
        }

        //deal with the partial block of associated data
        //in this program, we assume that the message length is multiple of bytes.
        if (  (adlen & 0x1f) != 0 )  {
              memset(plaintextblock, 0, 32);
              memcpy(plaintextblock, ad+i, adlen & 0x1f);
              aegis128L_enc_aut_step(plaintextblock, ciphertextblock, aegis128L_state);
        }

        //encrypt the plaintext
        for (i = 0; (i+32) <= (uint32_t)mlen; i += 32) {
              aegis128L_enc_aut_step(m+i, c+i, aegis128L_state);
        }

        // Deal with the partial block
        // In this program, we assume that the message length is a multiple of bytes.
        if (  (mlen & 0x1f) != 0 )  {
              memset(plaintextblock, 0, 32);
              memcpy(plaintextblock, m+i, mlen & 0x1f);
              aegis128L_enc_aut_step(plaintextblock, ciphertextblock, aegis128L_state);
              memcpy(c+i,ciphertextblock, mlen & 0x1f);
        }

        //finalization stage, we assume that the tag length is a multiple of bytes
        aegis128L_tag_generation(mlen, adlen, 16, mac, aegis128L_state);
        *clen = mlen + 16;
        memcpy(c+mlen, mac, 16);

        return 0;
}


/*--------------------------------*/

void Encrypt(uint8_t *block, size_t mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t adlen, uint8_t *c, uint8_t *roundKeys)
{
	//length of inputs and param
	size_t clen;
    crypto_aead_encrypt(c, &clen, block, mlen, ad, adlen, npub, key);
}


