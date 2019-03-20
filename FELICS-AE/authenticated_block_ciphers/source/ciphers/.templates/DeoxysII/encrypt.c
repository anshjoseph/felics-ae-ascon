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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"
#include "deoxys_common.h"


/*
** Deoxys encryption function
*/
void deoxys_aead_encrypt(const uint8_t *ass_data, size_t ass_data_len,
                         const uint8_t *message, size_t m_len,
                         const uint8_t *key,
                         const uint8_t *nonce,
                         uint8_t *ciphertext, size_t *c_len)
{

    uint64_t i;
    uint64_t j;
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
    memcpy(tweakey, key, KEY_SIZE);

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

void Encrypt(uint8_t *block, size_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t  adlen, uint8_t *c)
{
    size_t clen;
    deoxys_aead_encrypt(ad, adlen, block, mlen, key, npub, c, &clen);
}
