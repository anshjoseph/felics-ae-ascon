#include <stdint.h>

#include "cipher.h"
#include "ocb_common.h"


int Decrypt(uint8_t *block, size_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t  adlen, uint8_t *c)
{
    return ocb_crypt(block, key, npub, ad, adlen, c, mlen+TAGBYTES, 0);
}
