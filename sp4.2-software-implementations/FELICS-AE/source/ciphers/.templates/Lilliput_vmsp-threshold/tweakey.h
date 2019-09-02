#ifndef TWEAKEY_H
#define TWEAKEY_H

#include <stdint.h>

#include "constants.h"


void tweakey_state_init(
    uint8_t TK_X[TWEAKEY_BYTES],
    uint8_t TK_Y[TWEAKEY_BYTES],
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES]
);

void tweakey_X_state_extract(
    const uint8_t TK_Y[TWEAKEY_BYTES],
    uint8_t round_constant,
    uint8_t round_tweakey_Y[ROUND_TWEAKEY_BYTES] /* output */
);

void tweakey_Y_state_extract(
    const uint8_t TK_X[KEY_BYTES],
    uint8_t round_constant,
    uint8_t round_tweakey_X[ROUND_TWEAKEY_BYTES] /* output */
);

void tweakey_state_update(uint8_t TK_X[TWEAKEY_BYTES], uint8_t TK_Y[KEY_BYTES]);

#endif /* TWEAKEY_H */
