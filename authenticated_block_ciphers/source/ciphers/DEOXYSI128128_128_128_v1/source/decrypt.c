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


//#include "tweakableBC.h"

#include <string.h>
#include <stdlib.h>




#define GETRCON(r) ( ((uint32_t)READ_RCON_BYTE(rcon[r])<<24) ^ ((uint32_t)READ_RCON_BYTE(rcon[r])<<16) ^ ((uint32_t)READ_RCON_BYTE(rcon[r])<<8) ^ ((uint32_t)READ_RCON_BYTE(rcon[r])<<0) )
#define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] <<  8) ^ ((uint32_t)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (uint8_t)((st) >> 24); (ct)[1] = (uint8_t)((st) >> 16); (ct)[2] = (uint8_t)((st) >>  8); (ct)[3] = (uint8_t)(st); }



/*
** LFSR according to the position alpha (for alpha \in {1,2,3} )
*/
uint8_t choose_lfsr(uint8_t x, uint8_t alpha) {
  if( 1 == alpha ) return x;
  if( 2 == alpha ) return READ_LFSR_BYTE(lfsr2[x]);
  if( 3 == alpha ) return READ_LFSR_BYTE(lfsr4[x]);

	return 0;
}

/*
** Function G form the specifications
*/
void G(uint8_t tweakey[], uint8_t alpha) {
  int16_t i;
  for(i=0; i<16; i++) tweakey[i] = choose_lfsr(tweakey[i], alpha);
}

/*
** Function H form the specifications
*/
void H(uint8_t tweakey[]) {
  int16_t i;
  uint8_t tmp[16];
  for( i = 0; i<16; i++) tmp[READ_PERM_BYTE(perm[i])] = tweakey[i];
  memcpy(tweakey, tmp, 16);

}




/*
** Prepare the round subtweakeys for the decryption process
*/
uint8_t deoxysKeySetupDec256(uint32_t* rtweakey, 
                         const uint8_t* TweakKey,
                         int16_t no_tweakeys)
{

    int16_t i;
    int16_t j;
    int16_t Nr;
    uint32_t temp;

    /* Produce the round tweakeys used for the encryption */
    Nr=deoxysKeySetupEnc256(rtweakey, TweakKey, no_tweakeys);

    /* invert their order */
    for (i = 0, j = 4*Nr; i < j; i += 4, j -= 4) {
        temp = rtweakey[i    ]; rtweakey[i    ] = rtweakey[j    ]; rtweakey[j    ] = temp;
        temp = rtweakey[i + 1]; rtweakey[i + 1] = rtweakey[j + 1]; rtweakey[j + 1] = temp;
        temp = rtweakey[i + 2]; rtweakey[i + 2] = rtweakey[j + 2]; rtweakey[j + 2] = temp;
        temp = rtweakey[i + 3]; rtweakey[i + 3] = rtweakey[j + 3]; rtweakey[j + 3] = temp;
    }

    /* apply the inverse MixColumn transform to all round keys but the first and the last */
    for (i = 1; i <= Nr; i++) {
        rtweakey += 4;
        rtweakey[0] =
            READ_TW_DOUBLE_WORD(Td0[READ_TW_DOUBLE_WORD(Te4[(rtweakey[0] >> 24)       ]) & 0xff]) ^
            READ_TW_DOUBLE_WORD(Td1[READ_TW_DOUBLE_WORD(Te4[(rtweakey[0] >> 16) & 0xff]) & 0xff]) ^
            READ_TW_DOUBLE_WORD(Td2[READ_TW_DOUBLE_WORD(Te4[(rtweakey[0] >>  8) & 0xff]) & 0xff]) ^
            READ_TW_DOUBLE_WORD(Td3[READ_TW_DOUBLE_WORD(Te4[(rtweakey[0]      ) & 0xff]) & 0xff]);
        rtweakey[1] =
            READ_TW_DOUBLE_WORD(Td0[READ_TW_DOUBLE_WORD(Te4[(rtweakey[1] >> 24)       ]) & 0xff]) ^
            READ_TW_DOUBLE_WORD(Td1[READ_TW_DOUBLE_WORD(Te4[(rtweakey[1] >> 16) & 0xff]) & 0xff]) ^
            READ_TW_DOUBLE_WORD(Td2[READ_TW_DOUBLE_WORD(Te4[(rtweakey[1] >>  8) & 0xff]) & 0xff]) ^
            READ_TW_DOUBLE_WORD(Td3[READ_TW_DOUBLE_WORD(Te4[(rtweakey[1]      ) & 0xff]) & 0xff]);
        rtweakey[2] =
            READ_TW_DOUBLE_WORD(Td0[READ_TW_DOUBLE_WORD(Te4[(rtweakey[2] >> 24)       ]) & 0xff]) ^
            READ_TW_DOUBLE_WORD(Td1[READ_TW_DOUBLE_WORD(Te4[(rtweakey[2] >> 16) & 0xff]) & 0xff]) ^
            READ_TW_DOUBLE_WORD(Td2[READ_TW_DOUBLE_WORD(Te4[(rtweakey[2] >>  8) & 0xff]) & 0xff]) ^
            READ_TW_DOUBLE_WORD(Td3[READ_TW_DOUBLE_WORD(Te4[(rtweakey[2]      ) & 0xff]) & 0xff]);
        rtweakey[3] =
            READ_TW_DOUBLE_WORD(Td0[READ_TW_DOUBLE_WORD(Te4[(rtweakey[3] >> 24)       ]) & 0xff]) ^
            READ_TW_DOUBLE_WORD(Td1[READ_TW_DOUBLE_WORD(Te4[(rtweakey[3] >> 16) & 0xff]) & 0xff]) ^
            READ_TW_DOUBLE_WORD(Td2[READ_TW_DOUBLE_WORD(Te4[(rtweakey[3] >>  8) & 0xff]) & 0xff]) ^
            READ_TW_DOUBLE_WORD(Td3[READ_TW_DOUBLE_WORD(Te4[(rtweakey[3]      ) & 0xff]) & 0xff]);
    }
    return Nr;
}



/*
** Tweakable block cipher decryption function
*/
void aesTweakDecrypt(uint32_t tweakey_size,
                     const uint8_t ct[16],
                     const uint8_t key[],
                     uint8_t pt[16])
{

    uint32_t s0;
    uint32_t s1;
    uint32_t s2;
    uint32_t s3;
    uint32_t t0;
    uint32_t t1;
    uint32_t t2;
    uint32_t t3;
    uint32_t rk[4*17];

    /* Produce the round tweakeys */
    deoxysKeySetupDec256(rk, key, tweakey_size/128);

    /* Get the plaintext + key/tweak prewhitening */
    s0 = GETU32(ct     ) ^ rk[0];
    s1 = GETU32(ct +  4) ^ rk[1];
    s2 = GETU32(ct +  8) ^ rk[2];
    s3 = GETU32(ct + 12) ^ rk[3];

    /* Apply the inverse of the MixColumn transformation to use the Td AES tables */
    s0 =
        READ_TW_DOUBLE_WORD(Td0[READ_TW_DOUBLE_WORD(Te4[(s0 >> 24)       ]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Td1[READ_TW_DOUBLE_WORD(Te4[(s0 >> 16) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Td2[READ_TW_DOUBLE_WORD(Te4[(s0 >>  8) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Td3[READ_TW_DOUBLE_WORD(Te4[(s0      ) & 0xff]) & 0xff]);
    s1 =
        READ_TW_DOUBLE_WORD(Td0[READ_TW_DOUBLE_WORD(Te4[(s1 >> 24)       ]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Td1[READ_TW_DOUBLE_WORD(Te4[(s1 >> 16) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Td2[READ_TW_DOUBLE_WORD(Te4[(s1 >>  8) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Td3[READ_TW_DOUBLE_WORD(Te4[(s1      ) & 0xff]) & 0xff]);
    s2 =
        READ_TW_DOUBLE_WORD(Td0[READ_TW_DOUBLE_WORD(Te4[(s2 >> 24)       ]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Td1[READ_TW_DOUBLE_WORD(Te4[(s2 >> 16) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Td2[READ_TW_DOUBLE_WORD(Te4[(s2 >>  8) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Td3[READ_TW_DOUBLE_WORD(Te4[(s2      ) & 0xff]) & 0xff]);
    s3 =
        READ_TW_DOUBLE_WORD(Td0[READ_TW_DOUBLE_WORD(Te4[(s3 >> 24)       ]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Td1[READ_TW_DOUBLE_WORD(Te4[(s3 >> 16) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Td2[READ_TW_DOUBLE_WORD(Te4[(s3 >>  8) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Td3[READ_TW_DOUBLE_WORD(Te4[(s3      ) & 0xff]) & 0xff]);

    /* round 1: */
    t0 = READ_TW_DOUBLE_WORD(Td0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s1 & 0xff] )^ rk[ 4];
    t1 = READ_TW_DOUBLE_WORD(Td0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s2 & 0xff]) ^ rk[ 5];
    t2 = READ_TW_DOUBLE_WORD(Td0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s3 & 0xff]) ^ rk[ 6];
    t3 = READ_TW_DOUBLE_WORD(Td0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s0 & 0xff]) ^ rk[ 7];
    /* round 2: */
    s0 = READ_TW_DOUBLE_WORD(Td0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t1 & 0xff]) ^ rk[ 8];
    s1 = READ_TW_DOUBLE_WORD(Td0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t2 & 0xff]) ^ rk[ 9];
    s2 = READ_TW_DOUBLE_WORD(Td0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t3 & 0xff]) ^ rk[10];
    s3 = READ_TW_DOUBLE_WORD(Td0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t0 & 0xff]) ^ rk[11];
    /* round 3: */
    t0 = READ_TW_DOUBLE_WORD(Td0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s1 & 0xff]) ^ rk[12];
    t1 = READ_TW_DOUBLE_WORD(Td0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s2 & 0xff]) ^ rk[13];
    t2 = READ_TW_DOUBLE_WORD(Td0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s3 & 0xff]) ^ rk[14];
    t3 = READ_TW_DOUBLE_WORD(Td0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s0 & 0xff]) ^ rk[15];
    /* round 4: */
    s0 = READ_TW_DOUBLE_WORD(Td0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t1 & 0xff]) ^ rk[16];
    s1 = READ_TW_DOUBLE_WORD(Td0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t2 & 0xff]) ^ rk[17];
    s2 = READ_TW_DOUBLE_WORD(Td0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t3 & 0xff]) ^ rk[18];
    s3 = READ_TW_DOUBLE_WORD(Td0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t0 & 0xff]) ^ rk[19];
    /* round 5: */
    t0 = READ_TW_DOUBLE_WORD(Td0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s1 & 0xff]) ^ rk[20];
    t1 = READ_TW_DOUBLE_WORD(Td0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s2 & 0xff]) ^ rk[21];
    t2 = READ_TW_DOUBLE_WORD(Td0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s3 & 0xff]) ^ rk[22];
    t3 = READ_TW_DOUBLE_WORD(Td0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s0 & 0xff]) ^ rk[23];
    /* round 6: */
    s0 = READ_TW_DOUBLE_WORD(Td0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t1 & 0xff]) ^ rk[24];
    s1 = READ_TW_DOUBLE_WORD(Td0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t2 & 0xff]) ^ rk[25];
    s2 = READ_TW_DOUBLE_WORD(Td0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t3 & 0xff]) ^ rk[26];
    s3 = READ_TW_DOUBLE_WORD(Td0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t0 & 0xff]) ^ rk[27];
    /* round 7: */
    t0 = READ_TW_DOUBLE_WORD(Td0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s1 & 0xff]) ^ rk[28];
    t1 = READ_TW_DOUBLE_WORD(Td0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s2 & 0xff]) ^ rk[29];
    t2 = READ_TW_DOUBLE_WORD(Td0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s3 & 0xff]) ^ rk[30];
    t3 = READ_TW_DOUBLE_WORD(Td0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s0 & 0xff]) ^ rk[31];
    /* round 8: */
    s0 = READ_TW_DOUBLE_WORD(Td0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t1 & 0xff]) ^ rk[32];
    s1 = READ_TW_DOUBLE_WORD(Td0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t2 & 0xff]) ^ rk[33];
    s2 = READ_TW_DOUBLE_WORD(Td0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t3 & 0xff]) ^ rk[34];
    s3 = READ_TW_DOUBLE_WORD(Td0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t0 & 0xff]) ^ rk[35];
    /* round 9: */
    t0 = READ_TW_DOUBLE_WORD(Td0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s1 & 0xff]) ^ rk[36];
    t1 = READ_TW_DOUBLE_WORD(Td0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s2 & 0xff]) ^ rk[37];
    t2 = READ_TW_DOUBLE_WORD(Td0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s3 & 0xff]) ^ rk[38];
    t3 = READ_TW_DOUBLE_WORD(Td0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s0 & 0xff]) ^ rk[39];
    /* round 10: */
    s0 = READ_TW_DOUBLE_WORD(Td0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t1 & 0xff]) ^ rk[40];
    s1 = READ_TW_DOUBLE_WORD(Td0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t2 & 0xff]) ^ rk[41];
    s2 = READ_TW_DOUBLE_WORD(Td0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t3 & 0xff]) ^ rk[42];
    s3 = READ_TW_DOUBLE_WORD(Td0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t0 & 0xff]) ^ rk[43];
    /* round 11: */
    t0 = READ_TW_DOUBLE_WORD(Td0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s1 & 0xff]) ^ rk[44];
    t1 = READ_TW_DOUBLE_WORD(Td0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s2 & 0xff]) ^ rk[45];
    t2 = READ_TW_DOUBLE_WORD(Td0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s3 & 0xff]) ^ rk[46];
    t3 = READ_TW_DOUBLE_WORD(Td0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s0 & 0xff]) ^ rk[47];
    /* round 12: */
    s0 = READ_TW_DOUBLE_WORD(Td0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t1 & 0xff]) ^ rk[48];
    s1 = READ_TW_DOUBLE_WORD(Td0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t2 & 0xff]) ^ rk[49];
    s2 = READ_TW_DOUBLE_WORD(Td0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t3 & 0xff]) ^ rk[50];
    s3 = READ_TW_DOUBLE_WORD(Td0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t0 & 0xff]) ^ rk[51];
    /* round 13: */
    t0 = READ_TW_DOUBLE_WORD(Td0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s1 & 0xff]) ^ rk[52];
    t1 = READ_TW_DOUBLE_WORD(Td0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s2 & 0xff]) ^ rk[53];
    t2 = READ_TW_DOUBLE_WORD(Td0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s3 & 0xff]) ^ rk[54];
    t3 = READ_TW_DOUBLE_WORD(Td0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s0 & 0xff]) ^ rk[55];
    /* round 14: */
    s0 = READ_TW_DOUBLE_WORD(Td0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t1 & 0xff]) ^ rk[56];
    s1 = READ_TW_DOUBLE_WORD(Td0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t2 & 0xff]) ^ rk[57];
    s2 = READ_TW_DOUBLE_WORD(Td0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t3 & 0xff]) ^ rk[58];
    s3 = READ_TW_DOUBLE_WORD(Td0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t0 & 0xff]) ^ rk[59];

    if (384 == tweakey_size) {
        /* round 15: */
        t0 = READ_TW_DOUBLE_WORD(Td0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s1 & 0xff]) ^ rk[60];
        t1 = READ_TW_DOUBLE_WORD(Td0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s2 & 0xff]) ^ rk[61];
        t2 = READ_TW_DOUBLE_WORD(Td0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s3 & 0xff]) ^ rk[62];
        t3 = READ_TW_DOUBLE_WORD(Td0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[s0 & 0xff]) ^ rk[63];
        /* round 16: */
        s0 = READ_TW_DOUBLE_WORD(Td0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t1 & 0xff]) ^ rk[64];
        s1 = READ_TW_DOUBLE_WORD(Td0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t2 & 0xff] )^ rk[65];
        s2 = READ_TW_DOUBLE_WORD(Td0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t3 & 0xff]) ^ rk[66];
        s3 = READ_TW_DOUBLE_WORD(Td0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Td1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Td3[t0 & 0xff]) ^ rk[67];
    }

    /* Apply the MixColum to invert the last one performe in the Td table */
    s0 =
        READ_TW_DOUBLE_WORD(Te0[READ_TW_DOUBLE_WORD(Td4[(s0 >> 24)       ]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Te1[READ_TW_DOUBLE_WORD(Td4[(s0 >> 16) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Te2[READ_TW_DOUBLE_WORD(Td4[(s0 >>  8) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Te3[READ_TW_DOUBLE_WORD(Td4[(s0      ) & 0xff]) & 0xff]);
    s1 =
        READ_TW_DOUBLE_WORD(Te0[READ_TW_DOUBLE_WORD(Td4[(s1 >> 24)       ]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Te1[READ_TW_DOUBLE_WORD(Td4[(s1 >> 16) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Te2[READ_TW_DOUBLE_WORD(Td4[(s1 >>  8) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Te3[READ_TW_DOUBLE_WORD(Td4[(s1      ) & 0xff]) & 0xff]);
    s2 =
        READ_TW_DOUBLE_WORD(Te0[READ_TW_DOUBLE_WORD(Td4[(s2 >> 24)       ]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Te1[READ_TW_DOUBLE_WORD(Td4[(s2 >> 16) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Te2[READ_TW_DOUBLE_WORD(Td4[(s2 >>  8) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Te3[READ_TW_DOUBLE_WORD(Td4[(s2      ) & 0xff]) & 0xff]);
    s3 =
        READ_TW_DOUBLE_WORD(Te0[READ_TW_DOUBLE_WORD(Td4[(s3 >> 24)       ]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Te1[READ_TW_DOUBLE_WORD(Td4[(s3 >> 16) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Te2[READ_TW_DOUBLE_WORD(Td4[(s3 >>  8) & 0xff]) & 0xff]) ^
        READ_TW_DOUBLE_WORD(Te3[READ_TW_DOUBLE_WORD(Td4[(s3      ) & 0xff]) & 0xff]);

    /* Put the state into the ciphertext */
    PUTU32(pt     , s0);
    PUTU32(pt +  4, s1);
    PUTU32(pt +  8, s2);
    PUTU32(pt + 12, s3);

}

/**********************************************************************************
*** In Deoxys=/=-128-128, the tweak is on 128 bits:
***     tweak = <stage> || <nonce> || <blockNumber>
***  where we use:
***      4 bits for stage
***     64 bits for nonce
***     60 bits for blockNumber
***********************************************************************************/

/*
** Modifiy the nonce part in the tweak value
*/
 void set_nonce_in_tweak(uint8_t *tweak, const uint8_t *nonce) {
    tweak[0] = (tweak[0]&0xf0)     ^ (nonce[0] >> 4);
    tweak[1] = (nonce[0]&0xf) << 4 ^ (nonce[1] >> 4);
    tweak[2] = (nonce[1]&0xf) << 4 ^ (nonce[2] >> 4);
    tweak[3] = (nonce[2]&0xf) << 4 ^ (nonce[3] >> 4);
    tweak[4] = (nonce[3]&0xf) << 4 ^ (nonce[4] >> 4);
    tweak[5] = (nonce[4]&0xf) << 4 ^ (nonce[5] >> 4);
    tweak[6] = (nonce[5]&0xf) << 4 ^ (nonce[6] >> 4);
    tweak[7] = (nonce[6]&0xf) << 4 ^ (nonce[7] >> 4);
    tweak[8] = (nonce[7]&0xf) << 4;
}



/*
** Modifiy the stage value in the tweak value
*/
 void set_stage_in_tweak(uint8_t *tweak, const uint8_t value) {
    tweak[0]=(tweak[0] & 0xf) ^ value ;
}



/*
** Constant-time memcmp function
*/
uint8_t memcmp_const(const void * a, const void *b, const int32_t size)  {

    int32_t i;
    uint8_t result = 0;
    const uint8_t *_a = (const uint8_t *) a;
    const uint8_t *_b = (const uint8_t *) b;

    for (i = 0; i < size; i++) {
        result |= _a[i] ^ _b[i];
    }

    /* returns 0 if equal, nonzero otherwise */
    return result; 
}

/*
** XOR an input block to another input block
*/
 void xor_values(uint8_t *v1, const uint8_t *v2) {
    uint8_t i;
    for (i=0; i<16; i++) v1[i] ^= v2[i];
}



/*
** Deoxys decryption function
*/
uint8_t deoxys_aead_decrypt(const uint8_t *ass_data, size_t ass_data_len,
                       uint8_t *message, size_t *m_len,
                       const uint8_t *key,
                       const uint8_t *nonce,
                       const uint8_t *ciphertext, size_t c_len)
{

    uint64_t i;
    uint64_t j;
    uint8_t tweak[16];
    uint8_t tweakey[TWEAKEY_STATE_SIZE/8];
    uint8_t Auth[16];
    uint8_t last_block[16];
    uint8_t Checksum[16];
    uint8_t Final[16];
    uint8_t zero_block[16];
    uint8_t Pad[16];
    uint8_t Tag[16];
    uint8_t temp[16];

    /* Get the tag from the last 16 bytes of the ciphertext */
    memcpy(Tag, ciphertext+c_len-16, 16);

    /* Update c_len to the actual size of the ciphertext (i.e., without the tag) */
    c_len-=16;

    /* Fill the tweak with zeros (no nonce !!!) */
    memset(tweak, 0, sizeof(tweak));


    /* Fill the key(s) in the tweakey state */
    memcpy(tweakey, key, 16);

    /* Associated data */
    memset(Auth, 0, 16);

    if(ass_data_len) {

        set_stage_in_tweak(tweak, MSB_AD);
        i=0;
        while (16*(i+1) <= ass_data_len) {
            set_block_number_in_tweak(tweak, i );
            set_tweak_in_tweakey(tweakey, tweak);
            aesTweakEncrypt(TWEAKEY_STATE_SIZE, ass_data+16*i, tweakey, temp);
            xor_values(Auth, temp);
            i++;
        }

        /* Last block if incomplete */
        if ( ass_data_len > 16*i ) {
            memset(last_block, 0, 16);
            memcpy(last_block, ass_data+16*i, ass_data_len-16*i);
            last_block[ass_data_len-16*i]=0x80;
            set_stage_in_tweak(tweak, MSB_AD_LAST);
            set_block_number_in_tweak(tweak, i );
            set_tweak_in_tweakey(tweakey, tweak);
            aesTweakEncrypt(TWEAKEY_STATE_SIZE, last_block, tweakey, temp);
            xor_values(Auth, temp);
        }

    } /* if ass_data_len>0 */

    /* Ciphertext */
    memset(tweak, 0, sizeof(tweak));
    set_nonce_in_tweak(tweak, nonce);
    
    
    memset(Checksum, 0, 16);
    set_stage_in_tweak(tweak, MSB_M);
    i=0;
    while(16*(i+1)<=c_len) {
        set_tweak_in_tweakey(tweakey, tweak);
        set_block_number_in_tweak(tweak, i);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakDecrypt(TWEAKEY_STATE_SIZE, ciphertext+16*i, tweakey, message+16*i);
        xor_values(Checksum, message+16*i);
        i++;
    }

    /* Last block */
    /* If the block is full, i.e. M_last=epsilon */
    if (c_len == 16*i) {
        set_block_number_in_tweak(tweak, i);
        set_stage_in_tweak(tweak, MSB_CHKSUM_FULL);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(TWEAKEY_STATE_SIZE, Checksum, tweakey, Final);
        xor_values(Final, Auth);
        
        /* If the tags does not match, return error -1 */
        if( 0 != memcmp_const(Final, Tag, sizeof(Tag)) ) {
            memset( message, 0, c_len);
            return -1;
        }
        
    }
    else {
        
        /* Prepare the full-zero block */
        memset(zero_block, 0, 16);

        /* Prepare the tweak */
        set_stage_in_tweak(tweak, MSB_M_LAST_NONZERO);
        set_block_number_in_tweak(tweak, i);
        set_tweak_in_tweakey(tweakey, tweak);

        /* Encrypt */
        aesTweakEncrypt(TWEAKEY_STATE_SIZE, zero_block, tweakey, Pad);

        /* XOR the partial ciphertext */
        memset(last_block, 0, 16);
        memcpy(last_block, ciphertext+16*i, c_len-16*i);
        memset(Pad+c_len-16*i, 0, 16-(c_len-16*i));
        xor_values(last_block, Pad);
        last_block[c_len-16*i]=0x80;

        for (j=0; j<c_len-16*i; j++) {
            message[16*i+j]=last_block[j];
        }

        /* Update checksum */
        xor_values(Checksum, last_block);

        /* Verify the tag */
        set_stage_in_tweak(tweak, MSB_CHKSUM_NON_FULL);
        i++;
        set_block_number_in_tweak(tweak, i);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(TWEAKEY_STATE_SIZE, Checksum, tweakey, Final);
        xor_values(Final, Auth);

        /* If the tags does not match, return error -1 */
        if( 0 != memcmp_const(Final, Tag, sizeof(Tag)) ) {
	    memset( message, 0, c_len );
            return -1;
        }
    }

    *m_len=c_len;
    return 0;
}

int Decrypt(uint8_t *block, size_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t  adlen, uint8_t *c)
{
    return deoxys_aead_decrypt(ad, adlen, block, &mlen, key, npub, c, mlen+CRYPTO_ABYTES);
}
