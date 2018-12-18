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



/**********************************************************************************
*** In Deoxys=/=-128-128, the tweak is on 128 bits:
***     tweak = <stage> || <nonce> || <blockNumber>
***  where we use:
***      4 bits for stage
***     64 bits for nonce
***     60 bits for blockNumber
***********************************************************************************/


/*
** Modifiy the block number in the tweak value
*/
 void set_block_number_in_tweak(uint8_t *tweak, const int64_t block_no) {
    tweak[ 0] = ((block_no >> 56ULL) & 0xff);
    tweak[ 1] = ((block_no >> 48ULL) & 0xff);
    tweak[ 2] = ((block_no >> 40ULL) & 0xff);
    tweak[ 3] = (((block_no >> 31ULL) >> 1) & 0xff);
    tweak[ 4] = ((block_no >> 24ULL) & 0xff);
    tweak[ 5] = ((block_no >> 16ULL) & 0xff);
    tweak[ 6] = ((block_no >>  8ULL) & 0xff);
    tweak[ 7] = ((block_no >>  0ULL) & 0xff);
}

/*
** Modifiy the stage value in the tweak value
*/
 void set_stage_in_tweak(uint8_t *tweak, const uint8_t value) {
    tweak[0]=(tweak[0] & 0xf) ^ value ;
}

/*
** Update the tweak value in the tweakey word.
** In the case of Deoxys-BC-256, the tweakey word is composed of KEY || TWEAK.
** In the case of Deoxys-BC-384, the tweakey word is composed of KEY_2 || KEY_1 || TWEAK.
*/
 void set_tweak_in_tweakey(uint8_t *tweakey, uint8_t *tweak) {
#if TWEAKEY_STATE_SIZE==256
    memcpy(tweakey+16, tweak, 16);
#elif TWEAKEY_STATE_SIZE==384
    memcpy(tweakey+32, tweak, 16);
#endif
}



/*
** XOR an input block to another input block
*/
 void xor_values(uint8_t *v1, const uint8_t *v2) {
    uint8_t i;
    for (i=0; i<16; i++) v1[i] ^= v2[i];
}




/*
** Prepare the round subtweakeys for the encryption process
*/
int16_t deoxysKeySetupEnc256(int32_t* rtweakey,
                         const uint8_t* TweakKey,
                         int16_t no_tweakeys)
{

  int16_t r;
  uint8_t tweakey[3][16];
  uint8_t alpha[3];
  const uint32_t rcon_row1 = 0x01020408;
  int16_t Nr;

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
** Tweakable block cipher encryption function
*/
void aesTweakEncrypt(int16_t tweakey_size,
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
    
    int16_t i;
    for(i=0; i< 4*17; i++) rk[i]= 0;

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
    s3 = READ_TW_DOUBLE_WORD(Te0[(t3 >> 24) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te1[(t0 >> 16) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te2[(t1 >>  8) & 0xff]) ^ READ_TW_DOUBLE_WORD(Te3[t2 & 0xff]) ^ rk[51];
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





/* -------------------------- */
/*
** Deoxys encryption function
*/
void deoxys_aead_encrypt(const uint8_t *ass_data, int32_t ass_data_len,
                         const uint8_t *message, int32_t m_len,
                         const uint8_t *key,
                         const uint8_t *nonce,
                         uint8_t *ciphertext, int32_t *c_len)
{

    int64_t i;
    int32_t j;
    uint8_t tweak[16];
    uint8_t tweakey[TWEAKEY_STATE_SIZE/8];
    uint8_t Auth[16];
    uint8_t last_block[16];
    uint8_t temp[16];
    uint8_t tag[16];
    uint8_t nonce_plaintext[16];

    /* Fill the tweak with zeros */
    memset(tweak, 0, sizeof(tweak));

    /* Fill the key(s) in the tweakey state */
    memcpy(tweakey, key, 16);

    /* Associated data */
    memset(Auth, 0, 16);
    
    set_block_number_in_tweak(tweak + 0 , 0 );
    set_block_number_in_tweak(tweak + 8 , 0 );

    if(ass_data_len) {

        set_stage_in_tweak(tweak, MSB_AD);

        /* For each full input blocks */
        i=0;
        while (16*(i+1) <= ass_data_len) {

            /* Encrypt the current block */
            set_block_number_in_tweak(tweak + 8, i );
            set_tweak_in_tweakey(tweakey, tweak);
            aesTweakEncrypt(TWEAKEY_STATE_SIZE, ass_data+16*i, tweakey, temp);

            /* Update Auth value */
            xor_values(Auth, temp);

            /* Go on with the next block */
            i++;
        }

        /* Last block if incomplete */
        if ( ass_data_len > 16*i ) {
	  
            /* Prepare the last padded block */
            memset(last_block, 0, 16);
            memcpy(last_block, ass_data+16*i, ass_data_len-16*i);
            last_block[ass_data_len-16*i]=0x80;

            /* Encrypt the last block */
            set_stage_in_tweak(tweak, MSB_AD_LAST);
            set_block_number_in_tweak(tweak + 8 , i );
            set_tweak_in_tweakey(tweakey, tweak);
            aesTweakEncrypt(TWEAKEY_STATE_SIZE, last_block, tweakey, temp);

            /* Update the Auth value */
            xor_values(Auth, temp);
        }

    }/* if ass_data_len>0 */

    
    
    /*
     * Message
     * first pass
     */
    
    set_stage_in_tweak(tweak, MSB_M);
    i=0;
    while (16*(i+1) <= m_len) {
        set_block_number_in_tweak(tweak + 8, i);
	set_tweak_in_tweakey(tweakey, tweak);
	aesTweakEncrypt(TWEAKEY_STATE_SIZE, message + 16*i, tweakey, temp);
        xor_values(Auth, temp );
        i++;
    }
    /* Process incomplete block */
    if (m_len >  16*i) {
      
        /* Prepare the last padded block */
        memset(last_block, 0, 16);
        memcpy(last_block, message+16*i, m_len-16*i);
        last_block[m_len-16*i]=0x80;

        set_stage_in_tweak(tweak, MSB_M_LAST_NONZERO );
        set_block_number_in_tweak(tweak + 8 , i );
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(TWEAKEY_STATE_SIZE, last_block, tweakey, temp);
	
        xor_values(Auth, temp );
    } 



    /* Last encryption */
    set_stage_in_tweak(tweak, MSB_M_LAST_ZERO );
    memcpy( tweak + 1, nonce, 15);


    set_tweak_in_tweakey(tweakey, tweak);
    aesTweakEncrypt(TWEAKEY_STATE_SIZE, Auth, tweakey, tag );


    
    /*
     * Message
     * second pass
     */

    memset( nonce_plaintext, 0, 1 );	
    memcpy( nonce_plaintext + 1, nonce, 15 );

    memcpy(tweak, tag, 16 );
    tweak[0] = 0x80 ^ (tweak[0] & 0x7f);
    
    uint8_t temp_tweak[16];
    memcpy( temp_tweak, tweak, 16 );

    i = 0;
    while (16*(i+1) <= m_len) {

        temp_tweak[ 8] = tweak[ 8] ^ ((i>>56) & 0xff );
        temp_tweak[ 9] = tweak[ 9] ^ ((i>>48) & 0xff );
        temp_tweak[10] = tweak[10] ^ ((i>>40) & 0xff );
        temp_tweak[11] = tweak[11] ^ ((i>>32) & 0xff );
        temp_tweak[12] = tweak[12] ^ ((i>>24) & 0xff );
        temp_tweak[13] = tweak[13] ^ ((i>>16) & 0xff );
        temp_tweak[14] = tweak[14] ^ ((i>> 8) & 0xff );
        temp_tweak[15] = tweak[15] ^ ((i>> 0) & 0xff );

        set_tweak_in_tweakey(tweakey, temp_tweak);
        aesTweakEncrypt(TWEAKEY_STATE_SIZE, nonce_plaintext , tweakey, ciphertext + 16*i );
        xor_values(ciphertext + 16*i, message + 16*i );
        i++;
    }

    
    /* Impartial block */
    if (m_len >  16*i) {
        temp_tweak[ 8] = tweak[ 8] ^ ((i>>56) & 0xff );
        temp_tweak[ 9] = tweak[ 9] ^ ((i>>48) & 0xff );
        temp_tweak[10] = tweak[10] ^ ((i>>40) & 0xff );
        temp_tweak[11] = tweak[11] ^ ((i>>32) & 0xff );
        temp_tweak[12] = tweak[12] ^ ((i>>24) & 0xff );
        temp_tweak[13] = tweak[13] ^ ((i>>16) & 0xff );
        temp_tweak[14] = tweak[14] ^ ((i>> 8) & 0xff );
        temp_tweak[15] = tweak[15] ^ ((i>> 0) & 0xff );
        set_tweak_in_tweakey(tweakey, temp_tweak);
        aesTweakEncrypt(TWEAKEY_STATE_SIZE, nonce_plaintext , tweakey, temp );
        for( j = 0; j < m_len - 16 * i; j ++)
            ciphertext[ 16 * i + j ] = message[ 16 * i + j] ^ temp[j];
    } 
    
    
    /* Append the authentication tag to the ciphertext */
    memcpy( ciphertext + m_len, tag, 16 ); 

    /* The authentication tag is one block long, i.e. 16 bytes */
    *c_len=m_len+16;

}


/*------------------------------*/

uint8_t crypto_aead_encrypt(
	uint8_t *c, int32_t *clen,
	const uint8_t *m, int32_t mlen,
	const uint8_t *ad, int32_t adlen,
	const uint8_t *nsec,
	const uint8_t *npub,
	uint8_t *k
	)
{
        int32_t outlen = 0;
    deoxys_aead_encrypt(ad, adlen, m, mlen, k, npub, c, &outlen);
    *clen = outlen;
    (void)nsec;
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
	
	uint8_t *adb;
	adb = (uint8_t *) malloc(adlen * sizeof(uint8_t) );
	memcpy(adb, ad, adlen);
	
	if(adlen !=16){
	crypto_aead_encrypt(
	c, &clen,
	block, mlen,
	adb, adlen,
	nsec,
	npub,
	key
	);}
	else if(adlen ==16){
	crypto_aead_encrypt(
	c, &clen,
	block, mlen,
	adb, adlen,
	nsec,
	npub,
	key
	);
	}
	
	free(adb);
	
}



