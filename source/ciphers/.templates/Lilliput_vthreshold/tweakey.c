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
#include "multiplications.h"
#include "random.h"
#include "tweakey.h"


#define LANES_NB       (TWEAKEY_BYTES/LANE_BYTES)
#define TWEAK_LANES_NB (TWEAK_BYTES/LANE_BYTES)
#define KEY_LANES_NB   (KEY_BYTES/LANE_BYTES)


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


void tweakey_state_extract(
    const uint8_t TK_X[TWEAKEY_BYTES],
    const uint8_t TK_Y[KEY_BYTES],
    uint8_t round_constant,
    uint8_t round_tweakey_X[ROUND_TWEAKEY_BYTES],
    uint8_t round_tweakey_Y[ROUND_TWEAKEY_BYTES]
)
{
    memset(round_tweakey_X, 0, ROUND_TWEAKEY_BYTES);
    memset(round_tweakey_Y, 0, ROUND_TWEAKEY_BYTES);

    for (size_t j=0; j<LANES_NB; j++)
    {
        const uint8_t *TKj_X = TK_X + j*LANE_BYTES;

        for (size_t k=0; k<LANE_BYTES; k++)
        {
            round_tweakey_X[k] ^= TKj_X[k];
        }
    }

    for (size_t j=0; j<KEY_LANES_NB; j++)
    {
        const uint8_t *TKj_Y = TK_Y + j*LANE_BYTES;

        for (size_t k=0; k<LANE_BYTES; k++)
        {
            round_tweakey_Y[k] ^= TKj_Y[k];
        }
    }

    round_tweakey_X[0] ^= round_constant;
}


typedef void (*matrix_multiplication)(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES]);

static void _multiply(uint8_t TKj[LANE_BYTES], matrix_multiplication alpha)
{
    RAM_DATA_BYTE TKj_old[LANE_BYTES];
    memcpy(TKj_old, TKj, LANE_BYTES);
    alpha(TKj_old, TKj);
}

void tweakey_state_update(uint8_t TK_X[TWEAKEY_BYTES], uint8_t TK_Y[KEY_BYTES])
{
    _multiply(TK_X + 0*LANE_BYTES, _multiply_M);
    _multiply(TK_X + 1*LANE_BYTES, _multiply_M2);

#if TWEAK_LANES_NB == 2         /* t=128 => Lilliput-II */
    _multiply(TK_X + (0+TWEAK_LANES_NB)*LANE_BYTES, _multiply_M3);
    _multiply(TK_Y + 0*LANE_BYTES, _multiply_M3);

    _multiply(TK_X + (1+TWEAK_LANES_NB)*LANE_BYTES, _multiply_M4);
    _multiply(TK_Y + 1*LANE_BYTES, _multiply_M4);

  #if LANES_NB >= 5
    _multiply(TK_X + (2+TWEAK_LANES_NB)*LANE_BYTES, _multiply_MR);
    _multiply(TK_Y + 2*LANE_BYTES, _multiply_MR);

  #if LANES_NB >= 6
    _multiply(TK_X + (3+TWEAK_LANES_NB)*LANE_BYTES, _multiply_MR2);
    _multiply(TK_Y + 3*LANE_BYTES, _multiply_MR2);
  #endif
  #endif

#else  /* TWEAK_LANES_NB == 3      t=192 => Lilliput-I */
    _multiply(TK_X + 2*LANE_BYTES, _multiply_M3);

    _multiply(TK_X + (0+TWEAK_LANES_NB)*LANE_BYTES, _multiply_M4);
    _multiply(TK_Y + 0*LANE_BYTES, _multiply_M4);

  #if LANES_NB >= 5
    _multiply(TK_X + (1+TWEAK_LANES_NB)*LANE_BYTES, _multiply_MR);
    _multiply(TK_Y + 1*LANE_BYTES, _multiply_MR);

  #if LANES_NB >= 6
    _multiply(TK_X + (2+TWEAK_LANES_NB)*LANE_BYTES, _multiply_MR2);
    _multiply(TK_Y + 2*LANE_BYTES, _multiply_MR2);

  #if LANES_NB >= 7
    _multiply(TK_X + (3+TWEAK_LANES_NB)*LANE_BYTES, _multiply_MR3);
    _multiply(TK_Y + 3*LANE_BYTES, _multiply_MR3);
  #endif
  #endif
  #endif

#endif
}
