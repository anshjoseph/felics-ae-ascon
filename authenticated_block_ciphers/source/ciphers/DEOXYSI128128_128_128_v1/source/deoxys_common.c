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
void G(uint8_t tweakey[], uint8_t alpha) {
  int i;
  for(i=0; i<16; i++) tweakey[i] = choose_lfsr(tweakey[i], alpha);
}

/*
** Function H form the specifications
*/
void H(uint8_t tweakey[]) {
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
