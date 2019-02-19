#include <stdint.h>

#include "cipher.h"
#include "ocb_common.h"


void Encrypt(uint8_t *block, size_t mlen, uint8_t *key, uint8_t *npub,
             uint8_t *ad, size_t adlen, uint8_t *c)
{
    ocb_crypt(c, key, npub, ad, adlen, block, mlen, 1);
}
