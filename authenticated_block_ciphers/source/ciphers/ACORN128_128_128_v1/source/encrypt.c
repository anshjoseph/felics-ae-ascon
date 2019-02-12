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
#include "constants.h"
#include "utils.h"

/*
  This is the optimized implementation of ACORN-128.

  In the implementation, we store the 293-bit register into 7 64-bit registers:
  293-bit register R:  r292 r291 r290 r289 r288 r287 r286 r285 ...... r5 r4 r3 r2 r1 r0

  state[0]:  r60  r59  r58  r57  ...... r2   r1   r0     (61 bits) (lsb: r0)
  state[1]:  r106 r105 r104 r103 ...... r63  r62  r61    (46 bits) (lsb: r61)
  state[2]:  r153 r152 r151 r150 ...... r109 r108 r107   (47 bits) (lsb: r107)
  state[3]:  r192 r191 r190 r189 ...... r156 r155 r154   (39 bits) (lsb: r154)
  state[4]:  r229 r228 r227 r226 ...... r195 r194 r193   (37 bits) (lsb: r193)
  state[5]:  r288 r287 r286 r285 ...... r232 r231 r230   (59 bits) (lsb: r230)
  state[6]:  r292 r291 r290 r289                         (4  bits) (lsb: r289)
*/

// encrypt 32 bit;
// used when cb = 0; so we can remove the operation (cb * ks)
void encrypt_32bits_fast(uint64_t *state, uint32_t plaintextword, uint32_t *ciphertextword, uint32_t ca)
{
    unsigned int f, ks;
    uint64_t word_244, word_23, word_160, word_111, word_66, word_196;
    uint64_t word_12,word_235;

	word_235 = state[5] >> 5;
	word_196 = state[4] >> 3;
	word_160 = state[3] >> 6;
	word_111 = state[2] >> 4;
	word_66  = state[1] >> 5;
	word_23  = state[0] >> 23;
    word_244 = state[5] >> 14;
	word_12  = state[0] >> 12;

    //update using those 6 LFSRs
	state[6] ^= (state[5] ^ word_235) & 0xffffffff;
	state[5] ^= (state[4] ^ word_196) & 0xffffffff;
	state[4] ^= (state[3] ^ word_160) & 0xffffffff;
	state[3] ^= (state[2] ^ word_111) & 0xffffffff;
	state[2] ^= (state[1] ^ word_66)  & 0xffffffff;
	state[1] ^= (state[0] ^ word_23)  & 0xffffffff;

	/*
    word_0   = state[0];
    word_107 = state[2];
    word_230 = state[5];
    word_154 = state[3];
    word_61  = state[1];
    word_193 = state[4];
    */

	//compute keystream
	ks = word_12 ^ state[3] ^ maj(word_235, state[1], state[4]) ^ ch(state[5], word_111, word_66);

    //f  = state[0] ^ (state[107] ^ 1) ^ maj(state[244], state[23], state[160]) ^ ch(state[230], state[111], state[66]) ^ (ca & state[196]) ^ (cb & (*ks));
	f = state[0] ^ (~state[2]) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca);  // ^ (cb & *ks);
    *ciphertextword = plaintextword ^ ks;
	f = f ^ plaintextword;
	state[6] = state[6] ^ ( (uint64_t)f << 4 );

    //shift by 32 bits
    state[0] = (state[0] >> 32) | ((state[1] & 0xffffffff) << 29);  //32-(64-61) = 29
    state[1] = (state[1] >> 32) | ((state[2] & 0xffffffff) << 14);  //32-(64-46) = 14
    state[2] = (state[2] >> 32) | ((state[3] & 0xffffffff) << 15);  //32-(64-47) = 15
    state[3] = (state[3] >> 32) | ((state[4] & 0xffffffff) << 7);   //32-(64-39) = 7
    state[4] = (state[4] >> 32) | ((state[5] & 0xffffffff) << 5);   //32-(64-37) = 5
    state[5] = (state[5] >> 32) | ((state[6] & 0xffffffff) << 27);  //32-(64-59) = 27
    state[6] =  state[6] >> 32;

    //perform encryption

    return;
}


//encrypt a message
void crypto_aead_encrypt(
	uint8_t *c,size_t *clen,
	const uint8_t *m,size_t mlen,
	const uint8_t *ad,size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
	)
{
    size_t i;
    uint8_t mac[16];
    uint32_t plaintextword, ciphertextword;

    uint64_t state[7];
    uint32_t ca, cb;

    //initialization stage
    acorn128_initialization_32bitversion(k, npub, state);

    //process the associated data
    ca = 0xffffffff;
    cb = 0xffffffff;
    for (i = 0; i < adlen/4; i = i+1)
    {
        encrypt_32bits(state, ((uint32_t*)ad)[i], &ciphertextword, ca, cb);
    }

    // if adlen is not a multiple of 4, we process the remaining bytes
    for (i = adlen & (uint64_t)0xfffffffffffffffc; i < adlen; i++)
    {
        plaintextword = ad[i];
        encrypt_8bits(state, plaintextword, &ciphertextword, ca, cb);
    }

    //256bits padding after the associated data
    acorn128_padding_256(state,cb);

    //process the plaintext
    ca = 0xffffffff;
    cb = 0;
    for (i = 0; i < mlen/4; i=i+1)
    {
        encrypt_32bits_fast(state, ((uint32_t*)m)[i], &(((uint32_t*)c)[i]), ca);  //&c[i], &ksword, ca, cb);
    }

    //if mlen is not a multiple of 32 bits, we process the remaining bytes.
    for (i = mlen & (uint64_t)0xfffffffffffffffc; i < mlen; i++)
    {
        plaintextword = m[i];
        encrypt_8bits(state, plaintextword, &ciphertextword, ca, cb);
        c[i] = ciphertextword;
    }

    //256 bits padding after the plaintext
    acorn128_padding_256(state,cb);

    //finalization stage, we assume that the tag length is a multiple of bytes
    acorn128_tag_generation_32bits_version(mac, state);
    *clen = mlen + 16;
    memcpy(c+mlen, mac, 16);
}


void Encrypt(uint8_t *block, size_t mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t  adlen, uint8_t *c, uint8_t *roundKeys)
{
    size_t clen;
    crypto_aead_encrypt(c, &clen, block, mlen, ad, adlen, npub, key);
}
