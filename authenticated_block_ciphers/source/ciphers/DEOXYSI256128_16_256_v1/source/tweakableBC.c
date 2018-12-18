/*
 * Deoxys-I-128 Reference C Implementation
 *
 * Copyright 2016:
 *     Jeremy Jean <JJean@ntu.edu.sg>
 *     Ivica Nikolic <inikolic@ntu.edu.sg>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */



#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "tweakableBC.h"
#include "constants.h"

#define GETRCON(r) ( ((uint32_t)READ_RCON_BYTE(rcon[r])<<24) ^ ((uint32_t)READ_RCON_BYTE(rcon[r])<<16) ^ ((uint32_t)READ_RCON_BYTE(rcon[r])<<8) ^ ((uint32_t)READ_RCON_BYTE(rcon[r])<<0) )
#define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] <<  8) ^ ((uint32_t)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (uint8_t)((st) >> 24); (ct)[1] = (uint8_t)((st) >> 16); (ct)[2] = (uint8_t)((st) >>  8); (ct)[3] = (uint8_t)(st); }



/*
** LFSR according to the position alpha (for alpha \in {1,2,3} )
*/
uint8_t choose_lfsr (uint8_t x, uint8_t alpha) {
  if( 1 == alpha ) return x;
  if( 2 == alpha ) return READ_LFSR_BYTE(lfsr2[x]);
  if( 3 == alpha ) return READ_LFSR_BYTE(lfsr4[x]);

	return 0;
}

/*
** Function G form the specifications
*/
void G (uint8_t tweakey[], uint8_t alpha) {
  int i;
  for(i=0; i<16; i++) tweakey[i] = choose_lfsr (tweakey[i], alpha);
}

/*
** Function H form the specifications
*/
void H (uint8_t tweakey[]) {
  int i;
  uint8_t tmp[16];
  for( i = 0; i<16; i++) tmp[READ_PERM_BYTE(perm[i])] = tweakey[i];
  memcpy (tweakey, tmp, 16);

}

/*
** Prepare the round subtweakeys for the encryption process
*/
int deoxysKeySetupEnc256(uint32_t* rtweakey,
                         const uint8_t* TweakKey,
                         const int no_tweakeys)
{

  int r;
  uint8_t tweakey[3][16];
  uint8_t alpha[3];
  const uint32_t rcon_row1 = 0x01020408;
  int Nr;

  memcpy (tweakey[0], TweakKey +  0, 16);
  memcpy (tweakey[1], TweakKey + 16, 16);

  if( 2 == no_tweakeys ){
    alpha[0] = 2;
    alpha[1] = 1;

    /* Number of rounds is 14 */
    Nr=14;

  } else if( 3 == no_tweakeys ){
    memcpy (tweakey[2], TweakKey + 32, 16);
    alpha[0] = 3;
    alpha[1] = 2;
    alpha[2] = 1;

    /* Number of rounds is 16 */
    Nr=16;

  } else {
		return -1;
  }

  /* For each rounds */
  for(r=0; r<=Nr; r++) {

    /* Produce the round tweakey */
    rtweakey[ 4*r + 0] = GETU32( tweakey[0] +  0 ) ^ GETU32( tweakey[1] +  0 ) ^ ((3==no_tweakeys)* GETU32( tweakey[2] +  0 )) ^ rcon_row1 ;
    rtweakey[ 4*r + 1] = GETU32( tweakey[0] +  4 ) ^ GETU32( tweakey[1] +  4 ) ^ ((3==no_tweakeys)* GETU32( tweakey[2] +  4 )) ^ GETRCON( r);
    rtweakey[ 4*r + 2] = GETU32( tweakey[0] +  8 ) ^ GETU32( tweakey[1] +  8 ) ^ ((3==no_tweakeys)* GETU32( tweakey[2] +  8 ));
    rtweakey[ 4*r + 3] = GETU32( tweakey[0] + 12 ) ^ GETU32( tweakey[1] + 12 ) ^ ((3==no_tweakeys)* GETU32( tweakey[2] + 12 ));

    /* Apply H and G functions */
    H (tweakey[0]);
    G (tweakey[0], alpha[0]);

    H (tweakey[1]);
    G (tweakey[1], alpha[1]);

    if (3 == no_tweakeys) {
      H (tweakey[2]);
      G (tweakey[2], alpha[2]);
    }

  }/*r*/

  return Nr;
}


/*
** Prepare the round subtweakeys for the decryption process
*/
int deoxysKeySetupDec256(uint32_t* rtweakey, 
                         const uint8_t* TweakKey,
                         int no_tweakeys)
{

    int i;
    int j;
    int Nr;
    uint32_t temp;

    /* Produce the round tweakeys used for the encryption */
    Nr=deoxysKeySetupEnc256 (rtweakey, TweakKey, no_tweakeys);

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
** Tweakable block cipher encryption function
*/
void aesTweakEncrypt(uint32_t tweakey_size,
                     const uint8_t pt[16],
                     const uint8_t key[],
                     uint8_t ct[16]) {

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
    deoxysKeySetupEnc256 (rk, key, tweakey_size/128);

    /* Get the plaintext + key/tweak prewhitening */
    s0 = GETU32(pt     ) ^ rk[0];
    s1 = GETU32(pt +  4) ^ rk[1];
    s2 = GETU32(pt +  8) ^ rk[2];
    s3 = GETU32(pt + 12) ^ rk[3];

    /* round 1: */
    t0 = READ_TW_DOUBLE_WORD(Te0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s3 & 0xff]) ^ rk[ 4];
    t1 = READ_TW_DOUBLE_WORD(Te0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s0 & 0xff]) ^ rk[ 5];
    t2 = READ_TW_DOUBLE_WORD(Te0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s1 & 0xff]) ^ rk[ 6];
    t3 = READ_TW_DOUBLE_WORD(Te0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s2 & 0xff]) ^ rk[ 7];
    /* round 2: */
    s0 = READ_TW_DOUBLE_WORD(Te0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t3 & 0xff]) ^ rk[ 8];
    s1 = READ_TW_DOUBLE_WORD(Te0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t0 & 0xff]) ^ rk[ 9];
    s2 = READ_TW_DOUBLE_WORD(Te0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t1 & 0xff]) ^ rk[10];
    s3 = READ_TW_DOUBLE_WORD(Te0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t2 & 0xff]) ^ rk[11];
    /* round 3: */
    t0 = READ_TW_DOUBLE_WORD(Te0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s3 & 0xff]) ^ rk[12];
    t1 = READ_TW_DOUBLE_WORD(Te0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s0 & 0xff]) ^ rk[13];
    t2 = READ_TW_DOUBLE_WORD(Te0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s1 & 0xff]) ^ rk[14];
    t3 = READ_TW_DOUBLE_WORD(Te0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s2 & 0xff]) ^ rk[15];
    /* round 4: */
    s0 = READ_TW_DOUBLE_WORD(Te0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t3 & 0xff]) ^ rk[16];
    s1 = READ_TW_DOUBLE_WORD(Te0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t0 & 0xff]) ^ rk[17];
    s2 = READ_TW_DOUBLE_WORD(Te0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t1 & 0xff]) ^ rk[18];
    s3 = READ_TW_DOUBLE_WORD(Te0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t2 & 0xff]) ^ rk[19];
    /* round 5: */
    t0 = READ_TW_DOUBLE_WORD(Te0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s3 & 0xff]) ^ rk[20];
    t1 = READ_TW_DOUBLE_WORD(Te0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s0 & 0xff]) ^ rk[21];
    t2 = READ_TW_DOUBLE_WORD(Te0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s1 & 0xff]) ^ rk[22];
    t3 = READ_TW_DOUBLE_WORD(Te0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s2 & 0xff]) ^ rk[23];
    /* round 6: */
    s0 = READ_TW_DOUBLE_WORD(Te0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t3 & 0xff]) ^ rk[24];
    s1 = READ_TW_DOUBLE_WORD(Te0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t0 & 0xff]) ^ rk[25];
    s2 = READ_TW_DOUBLE_WORD(Te0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t1 & 0xff]) ^ rk[26];
    s3 = READ_TW_DOUBLE_WORD(Te0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t2 & 0xff]) ^ rk[27];
    /* round 7: */
    t0 = READ_TW_DOUBLE_WORD(Te0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s3 & 0xff]) ^ rk[28];
    t1 = READ_TW_DOUBLE_WORD(Te0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s0 & 0xff]) ^ rk[29];
    t2 = READ_TW_DOUBLE_WORD(Te0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s1 & 0xff]) ^ rk[30];
    t3 = READ_TW_DOUBLE_WORD(Te0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s2 & 0xff]) ^ rk[31];
    /* round 8: */
    s0 = READ_TW_DOUBLE_WORD(Te0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t3 & 0xff]) ^ rk[32];
    s1 = READ_TW_DOUBLE_WORD(Te0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t0 & 0xff]) ^ rk[33];
    s2 = READ_TW_DOUBLE_WORD(Te0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t1 & 0xff]) ^ rk[34];
    s3 = READ_TW_DOUBLE_WORD(Te0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t2 & 0xff]) ^ rk[35];
    /* round 9: */
    t0 = READ_TW_DOUBLE_WORD(Te0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s3 & 0xff]) ^ rk[36];
    t1 = READ_TW_DOUBLE_WORD(Te0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s0 & 0xff]) ^ rk[37];
    t2 = READ_TW_DOUBLE_WORD(Te0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s1 & 0xff]) ^ rk[38];
    t3 = READ_TW_DOUBLE_WORD(Te0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s2 & 0xff]) ^ rk[39];
    /* round 10: */
    s0 = READ_TW_DOUBLE_WORD(Te0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t3 & 0xff]) ^ rk[40];
    s1 = READ_TW_DOUBLE_WORD(Te0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t0 & 0xff]) ^ rk[41];
    s2 = READ_TW_DOUBLE_WORD(Te0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t1 & 0xff]) ^ rk[42];
    s3 = READ_TW_DOUBLE_WORD(Te0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t2 & 0xff]) ^ rk[43];
    /* round 11: */
    t0 = READ_TW_DOUBLE_WORD(Te0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s3 & 0xff]) ^ rk[44];
    t1 = READ_TW_DOUBLE_WORD(Te0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s0 & 0xff]) ^ rk[45];
    t2 = READ_TW_DOUBLE_WORD(Te0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s1 & 0xff]) ^ rk[46];
    t3 = READ_TW_DOUBLE_WORD(Te0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s2 & 0xff]) ^ rk[47];
    /* round 12: */
    s0 = READ_TW_DOUBLE_WORD(Te0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t3 & 0xff]) ^ rk[48];
    s1 = READ_TW_DOUBLE_WORD(Te0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t0 & 0xff]) ^ rk[49];
    s2 = READ_TW_DOUBLE_WORD(Te0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t1 & 0xff]) ^ rk[50];
    s3 = READ_TW_DOUBLE_WORD(Te0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t2 & 0xff]) ^ rk[51];
    /* round 13: */
    t0 = READ_TW_DOUBLE_WORD(Te0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s3 & 0xff]) ^ rk[52];
    t1 = READ_TW_DOUBLE_WORD(Te0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s0 & 0xff]) ^ rk[53];
    t2 = READ_TW_DOUBLE_WORD(Te0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s1 & 0xff]) ^ rk[54];
    t3 = READ_TW_DOUBLE_WORD(Te0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s2 & 0xff]) ^ rk[55];
    /* round 14: */
    s0 = READ_TW_DOUBLE_WORD(Te0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t3 & 0xff]) ^ rk[56];
    s1 = READ_TW_DOUBLE_WORD(Te0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t0 & 0xff]) ^ rk[57];
    s2 = READ_TW_DOUBLE_WORD(Te0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t1 & 0xff]) ^ rk[58];
    s3 = READ_TW_DOUBLE_WORD(Te0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t2 & 0xff]) ^ rk[59];

    if (384 == tweakey_size) {
      /* round 15: */
      t0 = READ_TW_DOUBLE_WORD(Te0[s0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s3 & 0xff]) ^ rk[60];
      t1 = READ_TW_DOUBLE_WORD(Te0[s1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s0 & 0xff]) ^ rk[61];
      t2 = READ_TW_DOUBLE_WORD(Te0[s2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s1 & 0xff]) ^ rk[62];
      t3 = READ_TW_DOUBLE_WORD(Te0[s3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(s0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(s1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[s2 & 0xff]) ^ rk[63];
      /* round 16: */
      s0 = READ_TW_DOUBLE_WORD(Te0[t0 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t1 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t2 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t3 & 0xff]) ^ rk[64];
      s1 = READ_TW_DOUBLE_WORD(Te0[t1 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t2 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t3 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t0 & 0xff]) ^ rk[65];
      s2 = READ_TW_DOUBLE_WORD(Te0[t2 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t3 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t0 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t1 & 0xff]) ^ rk[66];
      s3 = READ_TW_DOUBLE_WORD(Te0[t3 >> 24]) ^ READ_TW_DOUBLE_WORD(Te1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t2 & 0xff]) ^ rk[67];
    }

    /* Put the state into the ciphertext */
    PUTU32(ct     , s0);
    PUTU32(ct +  4, s1);
    PUTU32(ct +  8, s2);
    PUTU32(ct + 12, s3);
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
    deoxysKeySetupDec256 (rk, key, tweakey_size/128);

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
