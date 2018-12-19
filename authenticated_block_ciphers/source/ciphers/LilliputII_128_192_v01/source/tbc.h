#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>

#include "parameters.h"


void lilliput_tbc_encrypt(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t message[BLOCK_BYTES],
    uint8_t ciphertext[BLOCK_BYTES]
);

void lilliput_tbc_decrypt(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t ciphertext[BLOCK_BYTES],
    uint8_t message[BLOCK_BYTES]
);

#endif /* CIPHER_H */
