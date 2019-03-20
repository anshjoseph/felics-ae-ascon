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
    uint8_t Checksum[16];
    uint8_t Final[16];
    uint8_t zero_block[16];
    uint8_t Pad[16];
    uint8_t temp[16];
    

    /* Fill the tweak with zeros (no nonce !!!) */
    memset(tweak, 0, sizeof(tweak));

    /* Fill the key(s) in the tweakey state */
    memcpy(tweakey, key, KEY_SIZE);
	
    /* Associated data */
    memset(Auth, 0, 16);
	
    if(ass_data_len) {
        set_stage_in_tweak(tweak, MSB_AD);
		
        /* For each full input blocks */
        i=0;
        while (16*(i+1) <= ass_data_len) {
	  		
            /* Encrypt the current block */
            set_block_number_in_tweak(tweak, i);
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
            set_block_number_in_tweak(tweak, i);
            set_tweak_in_tweakey(tweakey, tweak);
            aesTweakEncrypt(TWEAKEY_STATE_SIZE, last_block, tweakey, temp);

            /* Update the Auth value */
            xor_values(Auth, temp);
        }

    }/* if ass_data_len>0 */

    
    
    /* Message */
    memset(tweak, 0, sizeof(tweak));
    set_nonce_in_tweak(tweak, nonce);
    
    memset(Checksum, 0, 16);
    set_stage_in_tweak(tweak, MSB_M);
    i=0;
    while (16*(i+1) <= m_len) {
        xor_values(Checksum, message+16*i );
        set_block_number_in_tweak(tweak, i );
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(TWEAKEY_STATE_SIZE, message+16*i , tweakey, ciphertext+16*i );
        i++;
    }

    /* Process incomplete block */
    if (m_len > 16*i) {
        memset(last_block, 0, 16);
        memcpy(last_block, message +16*i, m_len-16*i);
        last_block[m_len-16*i]=0x80;
        xor_values(Checksum, last_block);

        /* Create the zero block for encryption */
        memset(zero_block, 0, 16);

        /* Encrypt it */
        set_stage_in_tweak(tweak, MSB_M_LAST_NONZERO);
        set_block_number_in_tweak(tweak, i);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(TWEAKEY_STATE_SIZE, zero_block, tweakey, Pad);

        for (j=0; j<m_len-16*i; j++) {
            ciphertext[16*i+j]=last_block[j] ^ Pad[j];
        }
        set_stage_in_tweak(tweak, MSB_CHKSUM_NON_FULL);
        i++;
        set_block_number_in_tweak(tweak, i);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(TWEAKEY_STATE_SIZE, Checksum, tweakey, Final);
    }
    else{
        set_block_number_in_tweak(tweak, i);
        set_stage_in_tweak(tweak, MSB_CHKSUM_FULL);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(TWEAKEY_STATE_SIZE, Checksum, tweakey, Final);
    }

    /* Append the authentication tag to the ciphertext */
    for (i=0; i<16; i++) {
        ciphertext[m_len+i]=Final[i] ^ Auth[i];
    }
	
    /* The authentication tag is one block long, i.e. 16 bytes */
    *c_len=m_len+16;

}

void Encrypt(uint8_t *block, size_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t  adlen, uint8_t *c)
{
    size_t clen;
    deoxys_aead_encrypt(ad, adlen, block, mlen, key, npub, c, &clen);
}
