#ifndef OCB_COMMON_H
#define OCB_COMMON_H

#include <stdint.h>

#include "parameters.h"

int ocb_crypt(uint8_t *out, uint8_t *k, uint8_t *n,
              uint8_t *a, size_t abytes,
              uint8_t *in, size_t inbytes, int encrypting);

#define KEYBYTES   CRYPTO_KEYBYTES
#define NONCEBYTES CRYPTO_NPUBBYTES
#define TAGBYTES   CRYPTO_ABYTES

#endif /* OCB_COMMON_H */
