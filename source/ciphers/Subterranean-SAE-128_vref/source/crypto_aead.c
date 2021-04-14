#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "subterranean_ref.h"
#include "api.h"

int crypto_aead_encrypt(uint8_t *c, size_t *clen, const uint8_t *m, size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k){
    /* Call AEAD function */
    subterranean_SAE_direct_encrypt(c, &c[mlen], k, 8*CRYPTO_KEYBYTES, npub, 8*CRYPTO_NPUBBYTES, 8*CRYPTO_ABYTES, ad, 8*adlen, m, 8*mlen);
    /* Compact output */
    *clen = mlen+CRYPTO_ABYTES;
    return 0;
}

int crypto_aead_decrypt(uint8_t *m, size_t *mlen, const uint8_t *c, size_t clen, const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k){
    unsigned char t[CRYPTO_ABYTES];
    int tags_match;
    /* Call AEAD function */
    tags_match = subterranean_SAE_direct_decrypt(m, t, k, 8*CRYPTO_KEYBYTES, npub, 8*CRYPTO_NPUBBYTES, &c[clen-CRYPTO_ABYTES], 8*CRYPTO_ABYTES, ad, 8*adlen, c, 8*(clen-CRYPTO_ABYTES));
    /* Compact output */
    *mlen = clen-CRYPTO_ABYTES;
    return tags_match;
}
