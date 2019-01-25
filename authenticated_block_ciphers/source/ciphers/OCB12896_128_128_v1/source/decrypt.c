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


#include <string.h>
#include <stdlib.h>





#define KEYBYTES   CRYPTO_KEYBYTES
#define NONCEBYTES CRYPTO_NPUBBYTES
#define TAGBYTES   CRYPTO_ABYTES

typedef uint8_t block[16];


/* ------------------------------------------------------------------------- */

static void hash(block result, const uint8_t *k,
                 const uint8_t *a, int32_t abytes, uint8_t *roundKeys) {

    block lstar, ldollar, offset, sum, tmp;
    int32_t i;
    
    /* Key-dependent variables */
    
    
    /* L_* = ENCIPHER(K, zeros(128)) */

		memset(tmp, 0, 16);
    
		memcpy( lstar, tmp, BLOCK_SIZE);
		EncryptAES(lstar, roundKeys);
    /* L_$ = double(L_*) */
    double_block(ldollar, lstar);
    
    
    /* Process any whole blocks */
    
    /* Sum_0 = zeros(128) */
    memset(sum, 0, 16);
    /* Offset_0 = zeros(128) */
    memset(offset, 0, 16);
    for (i=1; i<=abytes/16; i++, a = a + 16) {
        /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
        calc_L_i(tmp, ldollar, i);
        xor_block(offset, offset, tmp);
        /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i) */
        xor_block(tmp, offset, a);
        EncryptAES(tmp, roundKeys);
        xor_block(sum, sum, tmp);
    }
    

    /* Process any final partial block; compute final hash value */

    abytes = abytes % 16;  /* Bytes in final block */
    if (abytes > 0) {
        /* Offset_* = Offset_m xor L_* */
        xor_block(offset, offset, lstar);
        /* tmp = (A_* || 1 || zeros(127-bitlen(A_*))) xor Offset_* */
        memset(tmp, 0, 16);
        memcpy(tmp, a, abytes);
        tmp[abytes] = 0x80;
        xor_block(tmp, offset, tmp);
        /* Sum = Sum_m xor ENCIPHER(K, tmp) */
				EncryptAES(tmp, roundKeys);
        xor_block(sum, tmp, sum);
    }
    
    memcpy(result, sum, 16);
}


static uint8_t ocb_crypt( uint8_t *out, const uint8_t*k, const uint8_t *n,
                     const uint8_t *a, int32_t abytes,
                     const uint8_t *in, uint32_t inbytes, int32_t encrypting, uint8_t *roundKeys) {

    block lstar, ldollar, sum, offset, ktop, pad, nonce, tag, tmp, ad_hash;
    uint8_t stretch[24];
    uint32_t bottom, byteshift, bitshift, i;
    
    
    
    /* Setup AES and strip ciphertext of its tag */
    if ( ! encrypting ) {
         if (inbytes < TAGBYTES) return -1;
         inbytes -= TAGBYTES;
    }
     
    /* Key-dependent variables */

    /* L_* = ENCIPHER(K, zeros(128)) */
    memset(tmp, 0, 16);
		memcpy( lstar, tmp, BLOCK_SIZE);
		EncryptAES(lstar, roundKeys);    /* L_$ = double(L_*) */
    double_block(ldollar, lstar); 

    /* Nonce-dependent and per-encryption variables */

    /* Nonce = zeros(127-bitlen(N)) || 1 || N */
    memset(nonce,0,16);
    memcpy(&nonce[16-NONCEBYTES],n,NONCEBYTES);
    nonce[0] = (uint8_t)(((TAGBYTES * 8) % 128) << 1);
    nonce[16-NONCEBYTES-1] |= 0x01;
    /* bottom = str2num(Nonce[123..128]) */
    bottom = nonce[15] & 0x3F;
    /* Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6)) */
    nonce[15] &= 0xC0;
		memcpy( ktop, nonce, BLOCK_SIZE);
		EncryptAES(ktop, roundKeys);    /* Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]) */
    memcpy(stretch, ktop, 16);
    memcpy(tmp, &ktop[1], 8);
    xor_block(tmp, tmp, ktop);
    memcpy(&stretch[16],tmp,8);
    /* Offset_0 = Stretch[1+bottom..128+bottom] */
    byteshift = bottom/8;
    bitshift  = bottom%8;
    if (bitshift != 0)
        for (i=0; i<16; i++)
            offset[i] = (stretch[i+byteshift] << bitshift) |
                        (stretch[i+byteshift+1] >> (8-bitshift));
    else
        for (i=0; i<16; i++)
            offset[i] = stretch[i+byteshift];
    /* Checksum_0 = zeros(128) */
    memset(sum, 0, 16);
    
    

    /* Hash associated data */
    uint8_t *roundkeysb;
		roundkeysb = (uint8_t *) malloc(ROUND_KEYS_SIZE * sizeof(uint8_t) );
	
		memcpy(roundkeysb, roundKeys, ROUND_KEYS_SIZE);
    hash(ad_hash, k, a, abytes, roundkeysb);
    free(roundkeysb);
    
    //memcpy(tab0, in, 16);
    
	
    /* Process any whole blocks */
	//i=1;
    for (i=1; i<=inbytes/16; i++) {
    
        /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
        //memcpy(tab0, ldollar, 16);
        
        
        calc_L_i(tmp, ldollar, i);
        
        xor_block(offset, offset, tmp);
        
        
        xor_block(tmp, offset, in);
        
        
        if (encrypting) {
            /* Checksum_i = Checksum_{i-1} xor P_i */
            xor_block(sum, in, sum);
            /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i) */
						EncryptAES(tmp, roundKeys);
            xor_block(out, offset, tmp);
        } else {
            /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i) */
						
						DecryptAES(tmp, roundKeys);
						
            xor_block(out, offset, tmp);
            /* Checksum_i = Checksum_{i-1} xor P_i */
            xor_block(sum, out, sum);
            
        }
        
        in=in+16;
         out=out+16;
    }
    
    

    /* Process any final partial block and compute raw tag */

    inbytes = inbytes % 16;  /* Bytes in final block */
    if (inbytes > 0) {
        /* Offset_* = Offset_m xor L_* */
        xor_block(offset, offset, lstar);
        /* Pad = ENCIPHER(K, Offset_*) */
				memcpy( pad, offset, BLOCK_SIZE);
				EncryptAES(pad, roundKeys);        
        if (encrypting) {
            /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
            memset(tmp, 0, 16);
            memcpy(tmp, in, inbytes);
            tmp[inbytes] = 0x80;
            xor_block(sum, tmp, sum);
            /* C_* = P_* xor Pad[1..bitlen(P_*)] */
            xor_block(pad, tmp, pad);
            memcpy(out, pad, inbytes);
            out = out + inbytes;
        } else {
            /* P_* = C_* xor Pad[1..bitlen(C_*)] */
            memcpy(tmp, pad, 16);
            memcpy(tmp, in, inbytes);
            xor_block(tmp, pad, tmp);
            tmp[inbytes] = 0x80;     /* tmp == P_* || 1 || zeros(127-bitlen(P_*)) */
            memcpy(out, tmp, inbytes);
            /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
            xor_block(sum, tmp, sum);
            in = in + inbytes;
        }
    }
    
    /* Tag = ENCIPHER(K, Checksum xor Offset xor L_$) xor HASH(K,A) */
    xor_block(tmp, sum, offset);
    xor_block(tmp, tmp, ldollar);
    
		memcpy( tag, tmp, BLOCK_SIZE);
		EncryptAES(tag, roundKeys); 
	
	
	
    xor_block(tag, ad_hash, tag);
    
    
    
    
    if (encrypting) {
        memcpy(out, tag, TAGBYTES);
        return 0;
    } else
        return (memcmp(in,tag,TAGBYTES) ? -1 : 0);     /* Check for validity */
}


/* ------------------------------------------------------------------------- */
#define OCB_ENCRYPT 1
#define OCB_DECRYPT 0


/* ------------------------------------ */

int crypto_aead_decrypt(
	uint8_t *m, int32_t *mlen,
	uint8_t *nsec,
	const uint8_t *c, int32_t clen,
	const uint8_t *ad, int32_t adlen,
	const uint8_t *npub,
	uint8_t *k, uint8_t *roundKeys
	)
{
    *mlen = clen - TAGBYTES;
    
    uint8_t *cb;
	cb = (uint8_t *) malloc(clen * sizeof(uint8_t) );
	
	memcpy(cb, c, clen);
	
    
    uint8_t result = ocb_crypt(m, k, npub,
            ad, adlen, cb, clen, OCB_DECRYPT, roundKeys);
            
    free(cb);
    
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
	
	uint8_t *roundkeysb;
	roundkeysb = (uint8_t *) malloc(ROUND_KEYS_SIZE * sizeof(uint8_t) );
	
	memcpy(roundkeysb, roundKeys, ROUND_KEYS_SIZE);
	
	uint8_t *adb;
	adb = (uint8_t *) malloc(adlen * sizeof(uint8_t) );
	memcpy(adb, ad, adlen);
	
	if(adlen !=16){
	return crypto_aead_decrypt(
	block, &mlen,
	nsec,
	c, clen,
	adb, adlen,
	npub,
	key, roundkeysb
	);}
	else if(adlen ==16){
	return crypto_aead_decrypt(
	block, &mlen,
	nsec,
	c, clen,
	adb, adlen,
	npub,
	key, roundkeysb
	);
	}
	
	free(roundkeysb);
	free(adb);
	
}


