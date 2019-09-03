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

#include "felics/cipher.h"
#include "common.h"

// 32 steps of ACORN
static void acorn128_32steps_enc(uint8_t *state, const uint8_t *plaintextbyte, uint8_t *ciphertextbyte, uint8_t cabyte, uint8_t cbbyte)
{
    unsigned int i;
    uint8_t j,f;
    uint8_t byte_12, byte_235, byte_244, byte_23,  byte_160, byte_111, byte_66, byte_196;
    uint8_t byte_230,byte_193, byte_154, byte_107, byte_61;
    uint8_t tem;
    uint8_t *state_tem, ksbyte;

    state_tem = state;

    for (i = 0; i < 4; i++)
    {
        byte_12  = (state_tem[1]  >> 4) | (state_tem[2]  << 4);
        byte_235 = (state_tem[29] >> 3) | (state_tem[30] << 5);
        byte_244 = (state_tem[30] >> 4) | (state_tem[31] << 4);
        byte_23  = (state_tem[2]  >> 7) | (state_tem[3]  << 1);
        byte_160 =  state_tem[20];
        byte_111 = (state_tem[13] >> 7) | (state_tem[14] << 1);
        byte_66  = (state_tem[8]  >> 2) | (state_tem[9]  << 6);
        byte_196 = (state_tem[24] >> 4) | (state_tem[25] << 4);

        byte_230 = (state_tem[28] >> 6) | (state_tem[29] << 2);
        byte_193 = (state_tem[24] >> 1) | (state_tem[25] << 7);
        byte_154 = (state_tem[19] >> 2) | (state_tem[20] << 6);
        byte_107 = (state_tem[13] >> 3) | (state_tem[14] << 5);
        byte_61  = (state_tem[7]  >> 5) | (state_tem[8]  << 3);

        tem = byte_235 ^ byte_230;
        state_tem[36] ^= tem << 1;
        state_tem[37] ^= tem >> 7;

        tem = byte_196 ^ byte_193;
        byte_230 ^= tem;
        state_tem[28] ^= tem << 6;
        state_tem[29] ^= tem >> 2;

        tem = byte_160 ^ byte_154;
        byte_193  ^= tem;
        state_tem[24] ^= tem << 1;
        state_tem[25] ^= tem >> 7;

        tem = byte_111 ^ byte_107;
        byte_154  ^= tem;
        state_tem[19] ^= tem << 2;
        state_tem[20] ^= tem >> 6;

        tem = byte_66 ^ byte_61;
        byte_107  ^= tem;
        state_tem[13] ^= tem << 3;
        state_tem[14] ^= tem >> 5;

        tem = byte_23 ^ state_tem[0];
        byte_61  ^= tem;
        state_tem[7] ^= tem << 5;
        state_tem[8] ^= tem >> 3;

        ksbyte = byte_12 ^ byte_154 ^ maj(byte_235, byte_61, byte_193) ^ ch(byte_230, byte_111, byte_66);

        *(ciphertextbyte+i) = *(plaintextbyte+i) ^ ksbyte;

        f = state_tem[0] ^ (~byte_107) ^ maj(byte_244, byte_23, byte_160) ^ (cabyte & byte_196) ^ (cbbyte & ksbyte);
        f ^= *(plaintextbyte+i);

        state_tem[36] ^= (f << 5);
        state_tem[37] ^= (f >> 3);

        state_tem++;
    }

    //shift by 32-bit positions
    for (j = 0; j <= 36; j++) state[j] = state[j+4];
    state[37] = 0;
    state[38] = 0;
    state[39] = 0;
    state[40] = 0;
}

// 8 steps of ACORN
static void acorn128_8steps_enc(uint8_t *state, const uint8_t *plaintextbyte, uint8_t *ciphertextbyte, uint8_t cabyte, uint8_t cbbyte)
{
    uint8_t j,f;
    uint8_t byte_12, byte_235, byte_244, byte_23,  byte_160, byte_111, byte_66, byte_196;
    uint8_t byte_230,byte_193, byte_154, byte_107, byte_61;
    uint8_t tem, ksbyte;

    byte_12  = (state[1]  >> 4) | (state[2]  << 4);
    byte_235 = (state[29] >> 3) | (state[30] << 5);
    byte_244 = (state[30] >> 4) | (state[31] << 4);
    byte_23  = (state[2]  >> 7) | (state[3]  << 1);
    byte_160 =  state[20];
    byte_111 = (state[13] >> 7) | (state[14] << 1);
    byte_66  = (state[8]  >> 2) | (state[9]  << 6);
    byte_196 = (state[24] >> 4) | (state[25] << 4);

    byte_230 = (state[28] >> 6) | (state[29] << 2);
    byte_193 = (state[24] >> 1) | (state[25] << 7);
    byte_154 = (state[19] >> 2) | (state[20] << 6);
    byte_107 = (state[13] >> 3) | (state[14] << 5);
    byte_61  = (state[7]  >> 5) | (state[8]  << 3);

    tem = byte_235 ^ byte_230;
    state[36] ^= tem << 1;
    state[37] ^= tem >> 7;

    tem = byte_196 ^ byte_193;
    byte_230 ^= tem;
    state[28] ^= tem << 6;
    state[29] ^= tem >> 2;

    tem = byte_160 ^ byte_154;
    byte_193  ^= tem;
    state[24] ^= tem << 1;
    state[25] ^= tem >> 7;

    tem = byte_111 ^ byte_107;
    byte_154  ^= tem;
    state[19] ^= tem << 2;
    state[20] ^= tem >> 6;

    tem = byte_66 ^ byte_61;
    byte_107  ^= tem;
    state[13] ^= tem << 3;
    state[14] ^= tem >> 5;

    tem = byte_23 ^ state[0];
    byte_61  ^= tem;
    state[7] ^= tem << 5;
    state[8] ^= tem >> 3;

    ksbyte = byte_12 ^ byte_154 ^ maj(byte_235, byte_61, byte_193) ^ ch(byte_230, byte_111, byte_66);

    *ciphertextbyte = *plaintextbyte ^ ksbyte;

    f = state[0] ^ (~byte_107) ^ maj(byte_244, byte_23, byte_160) ^ (cabyte & byte_196) ^ (cbbyte & ksbyte);
    f ^= *plaintextbyte;

    //shift by 8-bit positions
    state[36] ^= (f << 5);
    state[37] ^= (f >> 3);
    for (j = 0; j <= 36; j++) state[j] = state[j+1];
    state[37] = 0;
}

// The initialization state of ACORN
/* The input to initialization is the 128-bit key; 128-bit IV;*/
static void acorn128_initialization(const uint8_t *key, const uint8_t *iv, uint8_t *state)
{
    uint8_t j;
    uint8_t t;
    uint8_t tem[4] = {0,0,0,0};

    //initialize the state to 0
    for (j = 0; j <= 37+3; j++) state[j] = 0;

    //run the cipher for 1792 steps

    //load the key
    for (j = 0;  j < 16;  j = j+4)
    {
        acorn128_32steps_enc(state, &(key[j]), tem, 0xff, 0xff);
    }

    //load the iv
    for (j = 16;  j < 32;  j = j+4)
    {
        acorn128_32steps_enc(state, &(iv[j-16]), tem, 0xff, 0xff);
    }

    //bit "1" is padded
    for (j = 32;  j < 33; j++)
    {
        t = key[j&0xf] ^ 1;
        acorn128_8steps_enc(state, &t, tem, 0xff, 0xff);
    }

    for (j = 33;  j < 36; j++)
    {
        acorn128_8steps_enc(state, &(key[j&0xf]), tem, 0xff, 0xff);
    }

    for (j = 36;  j < 224; j=j+4)
    {
        acorn128_32steps_enc(state, &(key[j&0xf]), tem, 0xff, 0xff);
    }
}

//the finalization state of acorn
static void acorn128_tag_generation(uint8_t maclen, uint8_t *mac, uint8_t *state)
{
    uint8_t i;
    uint8_t plaintextbyte[4]  = {0,0,0,0};
    uint8_t ciphertextbyte[4] = {0,0,0,0};

    for (i = 0; i < (768-128)/8; i = i+4)
    {
        acorn128_32steps_enc(state, plaintextbyte, ciphertextbyte, 0xff, 0xff);
    }

    for (i = 0; i < maclen; i++)
    {
        acorn128_8steps_enc(state, plaintextbyte, ciphertextbyte, 0xff, 0xff);
        mac[i] = *ciphertextbyte;
    }
}

// the 256-step padding
// cb = 0xff for the padding after the associated data;
// cb = 0 for the padding after the plaintext.
static void acorn128_fixed_padding_256(uint8_t *state, uint8_t cb)
{
    uint8_t i;
    uint8_t plaintextbyte[4]  = {0,0,0,0};
    uint8_t ciphertextbyte[4] = {0,0,0,0};
    uint8_t ca;

    plaintextbyte[0] = 0x1;
    ca = 0xff;
    acorn128_8steps_enc(state, plaintextbyte, ciphertextbyte, ca, cb);

    plaintextbyte[0] = 0;
    for (i = 1; i < 4; i++)
    {
        acorn128_8steps_enc(state, plaintextbyte, ciphertextbyte, ca, cb);
    }

    for (i = 4; i < 128/8; i=i+4)
    {
        acorn128_32steps_enc(state, plaintextbyte, ciphertextbyte, ca, cb);
    }

    ca = 0;
    for (i = 0; i < 128/8; i=i+4)
    {
        acorn128_32steps_enc(state, plaintextbyte, ciphertextbyte, ca, cb);
    }
}

// encrypt a message
int crypto_aead_encrypt(
	uint8_t *c,size_t *clen,
	const uint8_t *m,size_t mlen,
	const uint8_t *ad,size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
	)
{
    size_t i;
    uint8_t mac[16];
    uint8_t ciphertextbyte[4] = {0,0,0,0};
    uint8_t state[38+3];
    uint8_t ca, cb;

    //initialization stage
    acorn128_initialization(k, npub, state);

    //process the associated data
    ca = 0xff;
    cb = 0xff;
    for (i = 0; i < (adlen & 0xfffffffffffffffcULL); i = i+4)
    {
        acorn128_32steps_enc(state, &(ad[i]), ciphertextbyte, ca, cb);
    }

    for (i = adlen & 0xfffffffffffffffcULL; i < adlen; i=i+1)
    {
        acorn128_8steps_enc(state, &(ad[i]), ciphertextbyte, ca, cb);
    }

    acorn128_fixed_padding_256(state, cb);

    //process the plaintext
    ca = 0xff;
    cb = 0;

    for (i = 0; i < (mlen&0xfffffffffffffffcULL); i=i+4)
    {
        acorn128_32steps_enc(state, &(m[i]), &c[i], ca, cb);
    }

    for (i = mlen&0xfffffffffffffffcULL; i < mlen; i=i+1)
    {
        acorn128_8steps_enc(state, &(m[i]), &c[i], ca, cb);
    }

    acorn128_fixed_padding_256(state, cb);

    //finalization stage, we assume that the tag length is a multiple of bytes
    acorn128_tag_generation(16, mac, state);
    *clen = mlen + 16;
    memcpy(c+mlen, mac, 16);

    return 0;
}
