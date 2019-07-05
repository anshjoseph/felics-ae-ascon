#include <stdint.h>
#include <string.h>

#include "cipher.h"

#include "multiplications.h"
#include "parameters.h"
#include "tweakey.h"


#define LANES_NB (TWEAKEY_BYTES/LANE_BYTES)


void tweakey_state_init(
    uint8_t TK[TWEAKEY_BYTES],
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES]
)
{
    memcpy(TK,             tweak, TWEAK_BYTES);
    memcpy(TK+TWEAK_BYTES, key,   KEY_BYTES);
}


void tweakey_state_extract(
    const uint8_t TK[TWEAKEY_BYTES],
    uint8_t round_constant,
    uint8_t round_tweakey[ROUND_TWEAKEY_BYTES]
)
{
    memset(round_tweakey, 0, ROUND_TWEAKEY_BYTES);

    for (size_t j=0; j<LANES_NB; j++)
    {
        const uint8_t *TKj = TK + j*LANE_BYTES;

        for (size_t k=0; k<LANE_BYTES; k++)
        {
            round_tweakey[k] ^= TKj[k];
        }
    }

    round_tweakey[0] ^= round_constant;
}


typedef void (*matrix_multiplication)(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES]);

static void _multiply(uint8_t TKj[LANE_BYTES], matrix_multiplication alpha)
{
    RAM_DATA_BYTE TKj_old[LANE_BYTES];
    memcpy(TKj_old, TKj, LANE_BYTES);
    alpha(TKj_old, TKj);
}

void tweakey_state_update(uint8_t TK[TWEAKEY_BYTES])
{
    _multiply(TK + 0*LANE_BYTES, _multiply_M);
    _multiply(TK + 1*LANE_BYTES, _multiply_M2);
    _multiply(TK + 2*LANE_BYTES, _multiply_M3);
    _multiply(TK + 3*LANE_BYTES, _multiply_M4);

#if LANES_NB >= 5
    _multiply(TK + 4*LANE_BYTES, _multiply_MR);

#if LANES_NB >= 6
    _multiply(TK + 5*LANE_BYTES, _multiply_MR2);

#if LANES_NB >= 7
    _multiply(TK + 6*LANE_BYTES, _multiply_MR3);
#endif
#endif
#endif
}
