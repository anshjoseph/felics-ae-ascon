/*
Implementation of the Lilliput-AE tweakable block cipher.

Authors, hereby denoted as "the implementer":
    Alexandre Adomnicai,
    Kévin Le Gouguec,
    Léo Reynaud,
    2019.

For more information, feedback or questions, refer to our website:
https://paclido.fr/lilliput-ae

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

This file provides a first-order threshold implementation of Lilliput-TBC's
tweakey schedule, where the tweak and the key are split into two shares.
*/

#include <stdint.h>
#include <string.h>

#include "felics/cipher.h"

#include "constants.h"
#include "random.h"
#include "tweakey.h"


#define LANE_BITS  64
#define LANE_BYTES (LANE_BITS/8)
#define LANES_NB   (TWEAKEY_BYTES/LANE_BYTES)


void tweakey_state_init(
    uint8_t TK_X[TWEAKEY_BYTES],
    uint8_t TK_Y[KEY_BYTES],
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES]
)
{
    RAM_DATA_BYTE SHARES_0[KEY_BYTES];
    randombytes(sizeof(SHARES_0), SHARES_0);

    memcpy(TK_Y, SHARES_0, KEY_BYTES);
    memcpy(TK_X, tweak, TWEAK_BYTES);

    for (size_t i=0; i<KEY_BYTES; i++){
        TK_X[i+TWEAK_BYTES] = key[i] ^ SHARES_0[i];
    }
}
