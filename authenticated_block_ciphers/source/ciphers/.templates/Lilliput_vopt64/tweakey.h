#ifndef TWEAKEY_H
#define TWEAKEY_H

#include <stdint.h>

#include "parameters.h"


#define LANE_BITS  64
#define LANE_BYTES (LANE_BITS/8)
#define LANES_NB   (TWEAKEY_BYTES/LANE_BYTES)


void tweakey_state_init(
    uint64_t TK[LANES_NB],
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES]
);

void tweakey_state_extract(
    const uint64_t TK[LANES_NB],
    uint8_t round_constant,
    uint8_t round_tweakey[ROUND_TWEAKEY_BYTES] /* output */
);

void tweakey_state_update(uint64_t TK[LANES_NB]);

#endif /* TWEAKEY_H */
