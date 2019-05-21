#include <stdint.h>
#include <string.h>

#include "cipher.h"

#include "parameters.h"
#include "tweakey.h"


#define LANE_BITS  64
#define LANE_BYTES (LANE_BITS/8)
#define LANES_NB   (TWEAKEY_BYTES/LANE_BYTES)


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


static void _multiply_M(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    y[7] = x[6];
    y[6] = x[5];
    y[5] = x[5]<<3 ^ x[4];
    y[4] = x[4]>>3 ^ x[3];
    y[3] = x[2];
    y[2] = x[6]<<2 ^ x[1];
    y[1] = x[0];
    y[0] = x[7];
}

static void _multiply_M2(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t x_M_5 = x[5]<<3 ^ x[4];
    uint8_t x_M_4 = x[4]>>3 ^ x[3];

    y[7] = x[5];
    y[6] = x_M_5;
    y[5] = x_M_5<<3 ^ x_M_4;
    y[4] = x_M_4>>3 ^ x[2];
    y[3] = x[6]<<2  ^ x[1];
    y[2] = x[5]<<2  ^ x[0];
    y[1] = x[7];
    y[0] = x[6];
}

static void _multiply_M3(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t x_M_5  = x[5]<<3  ^ x[4];
    uint8_t x_M_4  = x[4]>>3  ^ x[3];
    uint8_t x_M2_5 = x_M_5<<3 ^ x_M_4;
    uint8_t x_M2_4 = x_M_4>>3 ^ x[2];

    y[7] = x_M_5;
    y[6] = x_M2_5;
    y[5] = x_M2_5<<3 ^ x_M2_4;
    y[4] = x_M2_4>>3 ^ x[6]<<2 ^ x[1];
    y[3] = x[5]<<2   ^ x[0];
    y[2] = x_M_5<<2  ^ x[7];
    y[1] = x[6];
    y[0] = x[5];
}

#if LANES_NB >= 5
static void _multiply_MR(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    y[0] = x[1];
    y[1] = x[2];
    y[2] = x[3]    ^ x[4]>>3;
    y[3] = x[4];
    y[4] = x[5]    ^ x[6]<<3;
    y[5] = x[3]<<2 ^ x[6];
    y[6] = x[7];
    y[7] = x[0];
}

#if LANES_NB >= 6
static void _multiply_MR2(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t x_MR_4 = x[5] ^ x[6]<<3;

    y[0] = x[2];
    y[1] = x[3]    ^ x[4]>>3;
    y[2] = x[4]    ^ x_MR_4>>3;
    y[3] = x_MR_4;
    y[4] = x[3]<<2 ^ x[6]      ^ x[7]<<3;
    y[5] = x[4]<<2 ^ x[7];
    y[6] = x[0];
    y[7] = x[1];
}

#if LANES_NB >= 7
static void _multiply_MR3(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t x_MR_4  = x[5]    ^ x[6]<<3;
    uint8_t x_MR2_4 = x[3]<<2 ^ x[6]    ^ x[7]<<3;

    y[0] = x[3]      ^ x[4]>>3;
    y[1] = x[4]      ^ x_MR_4>>3;
    y[2] = x_MR_4    ^ x_MR2_4>>3;
    y[3] = x_MR2_4;
    y[4] = x[0]<<3   ^ x[4]<<2   ^ x[7];
    y[5] = x_MR_4<<2 ^ x[0];
    y[6] = x[1];
    y[7] = x[2];
}
#endif
#endif
#endif


void tweakey_state_update(uint8_t TK[TWEAKEY_BYTES])
{
    /* Skip lane 0, as it is multiplied by the identity matrix. */

    size_t j;
    uint8_t *TKj;
    RAM_DATA_BYTE TKj_old[LANE_BYTES];

    j = 1;
    TKj = TK + j*LANE_BYTES;
    memcpy(TKj_old, TKj, LANE_BYTES);
    _multiply_M(TKj_old, TKj);

    j = 2;
    TKj = TK + j*LANE_BYTES;
    memcpy(TKj_old, TKj, LANE_BYTES);
    _multiply_M2(TKj_old, TKj);

    j = 3;
    TKj = TK + j*LANE_BYTES;
    memcpy(TKj_old, TKj, LANE_BYTES);
    _multiply_M3(TKj_old, TKj);

#if LANES_NB >= 5
    j = 4;
    TKj = TK + j*LANE_BYTES;
    memcpy(TKj_old, TKj, LANE_BYTES);
    _multiply_MR(TKj_old, TKj);

#if LANES_NB >= 6
    j = 5;
    TKj = TK + j*LANE_BYTES;
    memcpy(TKj_old, TKj, LANE_BYTES);
    _multiply_MR2(TKj_old, TKj);

#if LANES_NB >= 7
    j = 6;
    TKj = TK + j*LANE_BYTES;
    memcpy(TKj_old, TKj, LANE_BYTES);
    _multiply_MR3(TKj_old, TKj);
#endif
#endif
#endif
}
