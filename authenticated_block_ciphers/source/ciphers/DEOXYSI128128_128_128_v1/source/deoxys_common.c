#include <stdint.h>
#include <string.h>

#include "constants.h"
#include "deoxys_common.h"


/*
** LFSR according to the position alpha (for alpha \in {1,2,3} )
*/
static uint8_t choose_lfsr(uint8_t x, uint8_t alpha) {
  if( 1 == alpha ) return x;
  if( 2 == alpha ) return READ_LFSR_BYTE(lfsr2[x]);
  if( 3 == alpha ) return READ_LFSR_BYTE(lfsr4[x]);

  return 0;
}

/*
** Function G form the specifications
*/
static void G(uint8_t tweakey[], uint8_t alpha) {
  int i;
  for(i=0; i<16; i++) tweakey[i] = choose_lfsr(tweakey[i], alpha);
}

/*
** Function H form the specifications
*/
static void H(uint8_t tweakey[]) {
  int i;
  uint8_t tmp[16];
  for( i = 0; i<16; i++) tmp[READ_PERM_BYTE(perm[i])] = tweakey[i];
  memcpy(tweakey, tmp, 16);

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
** Modifiy the block number in the tweak value
*/
void set_block_number_in_tweak(uint8_t *tweak, int64_t block_no) {
    tweak[ 8] = (tweak[8]&0xf0) ^ ((block_no >> 56ULL) & 0xf);
    tweak[ 9] = ((block_no >> 48ULL) & 0xff);
    tweak[10] = ((block_no >> 40ULL) & 0xff);
    tweak[11] = ((block_no >> 32ULL) & 0xff);
    tweak[12] = ((block_no >> 24ULL) & 0xff);
    tweak[13] = ((block_no >> 16ULL) & 0xff);
    tweak[14] = ((block_no >>  8ULL) & 0xff);
    tweak[15] = ((block_no >>  0ULL) & 0xff);
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
    int i;
    for (i=0; i<16; i++) v1[i] ^= v2[i];
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
    
    deoxysKeySetupEnc256(rk, key, tweakey_size/128);

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
** Prepare the round subtweakeys for the encryption process
*/
int deoxysKeySetupEnc256(uint32_t* rtweakey,
                         const uint8_t* TweakKey,
                         const int no_tweakeys)
{

  int r;
  uint8_t tweakey[3][16];
  uint8_t alpha[3];
  const int32_t rcon_row1 = 0x01020408;
  int Nr;

  memcpy(tweakey[0], TweakKey +  0, 16);
  memcpy(tweakey[1], TweakKey + 16, 16);

  if( 2 == no_tweakeys ){
    alpha[0] = 2;
    alpha[1] = 1;

    /* Number of rounds is 14 */
    Nr=14;

  } else if( 3 == no_tweakeys ){
    memcpy(tweakey[2], TweakKey + 32, 16);
    alpha[0] = 3;
    alpha[1] = 2;
    alpha[2] = 1;

    /* Number of rounds is 16 */
    Nr=16;

  } else {
      return 0;
  }

  /* For each rounds */
  for(r=0; r<=Nr; r++) {

    /* Produce the round tweakey */
    rtweakey[ 4*r + 0] = GETU32( tweakey[0] +  0 ) ^ GETU32( tweakey[1] +  0 ) ^ ((3==no_tweakeys)* GETU32( tweakey[2] +  0 )) ^ rcon_row1 ;
    rtweakey[ 4*r + 1] = GETU32( tweakey[0] +  4 ) ^ GETU32( tweakey[1] +  4 ) ^ ((3==no_tweakeys)* GETU32( tweakey[2] +  4 )) ^ GETRCON( r);
    rtweakey[ 4*r + 2] = GETU32( tweakey[0] +  8 ) ^ GETU32( tweakey[1] +  8 ) ^ ((3==no_tweakeys)* GETU32( tweakey[2] +  8 ));
    rtweakey[ 4*r + 3] = GETU32( tweakey[0] + 12 ) ^ GETU32( tweakey[1] + 12 ) ^ ((3==no_tweakeys)* GETU32( tweakey[2] + 12 ));

    /* Apply H and G functions */
    H(tweakey[0]);
    G(tweakey[0], alpha[0]);

    H(tweakey[1]);
    G(tweakey[1], alpha[1]);

    if (3 == no_tweakeys) {
      H(tweakey[2]);
      G(tweakey[2], alpha[2]);
    }

  }/*r*/

  return Nr;
}
