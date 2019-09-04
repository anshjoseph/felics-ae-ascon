/*
Implementation of the Lilliput-AE tweakable block cipher.

Authors, hereby denoted as "the implementer":
    Kévin Le Gouguec,
    2019.

For more information, feedback or questions, refer to our website:
https://paclido.fr/lilliput-ae

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

This file provides the implementation of Lilliput-TBC's tweakey schedule.
*/

#include <stdint.h>
#include <string.h>

#include "constants.h"
#include "tweakey.h"


void tweakey_state_init(
    uint8_t TK[TWEAKEY_BYTES],
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES]
)
{
    memcpy(TK,             tweak, TWEAK_BYTES);
    memcpy(TK+TWEAK_BYTES, key,   KEY_BYTES);
}
