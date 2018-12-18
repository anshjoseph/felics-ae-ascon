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


#include "tweakableBC.h"

#include <string.h>
#include <stdlib.h>




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
static void set_nonce_in_tweak(uint8_t *tweak, const uint8_t *nonce) {
    tweak[0] = (tweak[0] & 0xf0)     ^ (nonce[0] >> 4);
    tweak[1] = (nonce[0] & 0xf) << 4 ^ (nonce[1] >> 4);
    tweak[2] = (nonce[1] & 0xf) << 4 ^ (nonce[2] >> 4);
    tweak[3] = (nonce[2] & 0xf) << 4 ^ (nonce[3] >> 4);
    tweak[4] = (nonce[3] & 0xf) << 4 ^ (nonce[4] >> 4);
    tweak[5] = (nonce[4] & 0xf) << 4 ^ (nonce[5] >> 4);
    tweak[6] = (nonce[5] & 0xf) << 4 ^ (nonce[6] >> 4);
    tweak[7] = (nonce[6] & 0xf) << 4 ^ (nonce[7] >> 4);
    tweak[8] = (nonce[7] & 0xf) << 4;
}

/*
** Modifiy the block number in the tweak value
*/
static void set_block_number_in_tweak(uint8_t *tweak, const uint64_t block_no) {
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
static void set_stage_in_tweak(uint8_t *tweak, const uint8_t value) {
    tweak[0]=(tweak[0] & 0xf) ^ value ;
}

/*
** Update the tweak value in the tweakey word.
** In the case of Deoxys-BC-256, the tweakey word is composed of KEY || TWEAK.
** In the case of Deoxys-BC-384, the tweakey word is composed of KEY_2 || KEY_1 || TWEAK.
*/
static void set_tweak_in_tweakey(uint8_t *tweakey, uint8_t *tweak) {
#if TWEAKEY_STATE_SIZE==256
    memcpy(tweakey+16, tweak, 16);
#elif TWEAKEY_STATE_SIZE==384
    memcpy(tweakey+32, tweak, 16);
#endif
}

/*
** Constant-time memcmp function
*/
static int memcmp_const(const void * a, const void *b, const int32_t size)  {

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
static void xor_values(uint8_t *v1, const uint8_t *v2) {
    uint8_t i;
    for (i=0; i<16; i++) v1[i] ^= v2[i];
}



/*
** Deoxys decryption function
*/
int deoxys_aead_decrypt(const uint8_t *ass_data, int32_t ass_data_len,
                       uint8_t *message, int32_t *m_len,
                       const uint8_t *key,
                       const uint8_t *nonce,
                       const uint8_t *ciphertext, int32_t c_len)
{

    int32_t i;
    int32_t j;
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

    /* Fill the tweak from nonce */
    memset(tweak, 0, sizeof(tweak));

    /* Fill the key(s) in the tweakey state */
    memcpy(tweakey, key, 32);

    
    /* Associated data */
    memset(Auth, 0, 16);

    if(ass_data_len) {
        set_stage_in_tweak(tweak, MSB_AD);
        i=0;
        while (16*(i+1) <= ass_data_len) {
            set_block_number_in_tweak(tweak, i );
            set_tweak_in_tweakey(tweakey, tweak);
            aesTweakEncrypt(TWEAKEY_STATE_SIZE, ass_data+16*i , tweakey, temp);

            xor_values(Auth, temp);
            i++;
        }

        /* Last block if incomplete */
        if ( ass_data_len > 16*i ) {
            memset(last_block, 0, 16);
            memcpy(last_block, ass_data+16*i, ass_data_len-16*i);
            last_block[ass_data_len-16*i]=0x80;
            set_stage_in_tweak(tweak, MSB_AD_LAST);
            set_block_number_in_tweak(tweak, i);
            set_tweak_in_tweakey(tweakey, tweak);
            aesTweakEncrypt(TWEAKEY_STATE_SIZE, last_block, tweakey, temp);
            xor_values(Auth, temp);
        }
    }/* if ass_data_len>0 */

    
    /* Ciphertext */
    memset(tweak, 0, sizeof(tweak));
    set_nonce_in_tweak(tweak, nonce);

    memset(Checksum, 0, 16);
    set_stage_in_tweak(tweak, MSB_M);
    i=0;
    while(16*(i+1) <= c_len) {
        set_tweak_in_tweakey(tweakey, tweak);
        set_block_number_in_tweak(tweak, i );
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakDecrypt(TWEAKEY_STATE_SIZE, ciphertext+16*i , tweakey, message+16*i );

        xor_values(Checksum, message+16*i );
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

        /* Write the message block */
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

    /* Update the length of the plaintext */
    *m_len=c_len;
    
    return 0;
}

/* ------------------------------------ */

int crypto_aead_decrypt(
	uint8_t *m, int32_t *mlen,
	uint8_t *nsec,
	const uint8_t *c, int32_t clen,
	const uint8_t *ad, int32_t adlen,
	const uint8_t *npub,
	const uint8_t *k
	)
{
     int32_t outlen = *mlen;
    uint8_t result = deoxys_aead_decrypt(ad, adlen, m, &outlen, k, npub, c, clen);
    *mlen = outlen;
    (void)nsec;
    return result;
}



uint8_t Decrypt(uint8_t *block, int32_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, int32_t  adlen, uint8_t *c, uint8_t *roundKeys)
{
	/* Add here the cipher decryption implementation */

		static uint8_t *nsec;
	nsec = malloc(CRYPTO_NSECBYTES);
	
	//length of inputs and param
	int32_t clen = mlen + CRYPTO_ABYTES;
	
	if(adlen !=16){
	return crypto_aead_decrypt(
	block, &mlen,
	nsec,
	c, clen,
	ad, adlen,
	npub,
	key
	);}
	else if(adlen ==16){
	return crypto_aead_decrypt(
	block, &mlen,
	nsec,
	c, clen,
	ad, adlen,
	npub,
	key
	);
	}
	
}


