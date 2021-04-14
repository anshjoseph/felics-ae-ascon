/*
SUNDAE-GIFT
Prepared by: Siang Meng Sim
Email: crypto.s.m.sim@gmail.com
Date: 09 Feb 2019
*/

#include <stdlib.h>
#include "api.h"
#include "sundae.h"
#include "gift128.h"
#include "crypto_aead.h"


/*
 the code for the cipher implementation goes here,
 generating a ciphertext c[0],c[1],...,c[*clen-1]
 from a plaintext m[0],m[1],...,m[mlen-1]
 and associated data ad[0],ad[1],...,ad[adlen-1]
 and public message number npub[0],npub[1],...
 and secret key k[0],k[1],...
 */

int crypto_aead_encrypt(uint8_t *c, size_t *clen,
                        const uint8_t *m, size_t mlen,
                        const uint8_t *ad, size_t adlen,
                        const uint8_t *npub,
                        const uint8_t *k
                        )
{
    sundae_enc(npub,CRYPTO_NPUBBYTES,ad,adlen,m,mlen,k,c,0);
    *clen = mlen+16;
    return 0;
}

/*
 the code for the cipher implementation goes here,
 generating a plaintext m[0],m[1],...,m[*mlen-1]
 from a ciphertext c[0],c[1],...,c[clen-1]
 and associated data ad[0],ad[1],...,ad[adlen-1]
 and public message number npub[0],npub[1],...
 and secret key k[0],k[1],...
 */
int crypto_aead_decrypt(uint8_t *m, size_t *mlen,
                        const uint8_t *c, size_t clen,
                        const uint8_t *ad, size_t adlen,
                        const uint8_t *npub,
                        const uint8_t *k
                        )
{
    int result = sundae_dec(npub,CRYPTO_NPUBBYTES,ad,adlen,m,k,c,clen);
    *mlen = clen-16;
    return result;
}
