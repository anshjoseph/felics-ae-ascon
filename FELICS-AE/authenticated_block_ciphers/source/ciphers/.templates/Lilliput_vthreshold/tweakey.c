#include <stdint.h>
#include <string.h>

#include "cipher.h"

#include "parameters.h"
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


    for (size_t j=0; j<(KEY_BYTES / LANE_BYTES); j++)
    {
        const uint8_t *TKj_Y = TK_Y + j*LANE_BYTES;

        for (size_t k=0; k<LANE_BYTES; k++)
        {
            round_tweakey_Y[k] ^= TKj_Y[k];
        }
    }

    round_tweakey_X[0] ^= round_constant;
}


static void _multiply_M(const uint8_t X[LANE_BYTES], uint8_t Y[LANE_BYTES])
{
    Y[7] = X[6];
    Y[6] = X[5];
    Y[5] = X[5]<<3 ^ X[4];
    Y[4] = X[4]>>3 ^ X[3];
    Y[3] = X[2];
    Y[2] = X[6]<<2 ^ X[1];
    Y[1] = X[0];
    Y[0] = X[7];
}

static void _multiply_M2(const uint8_t X[LANE_BYTES], uint8_t Y[LANE_BYTES])
{
    uint8_t x15 = X[5]<<3 ^ X[4];
    uint8_t x14 = X[4]>>3 ^ X[3];

    Y[7] = X[5];
    Y[6] = x15;
    Y[5] = x15<<3  ^ x14;
    Y[4] = x14>>3  ^ X[2];
    Y[3] = X[6]<<2 ^ X[1];
    Y[2] = X[5]<<2 ^ X[0];
    Y[1] = X[7];
    Y[0] = X[6];
}

static void _multiply_M3(const uint8_t X[LANE_BYTES], uint8_t Y[LANE_BYTES])
{
    uint8_t x15 = X[5]<<3 ^ X[4];
    uint8_t x14 = X[4]>>3 ^ X[3];
    uint8_t x25 = x15<<3  ^ x14;
    uint8_t x24 = x14>>3  ^ X[2];

    Y[7] = x15;
    Y[6] = x25;
    Y[5] = x25<<3  ^ x24;
    Y[4] = x24>>3  ^ X[6]<<2 ^ X[1];
    Y[3] = X[5]<<2 ^ X[0];
    Y[2] = x15<<2  ^ X[7];
    Y[1] = X[6];
    Y[0] = X[5];
}

#if LANES_NB >= 5
static void _multiply_MR(const uint8_t X[LANE_BYTES], uint8_t Y[LANE_BYTES])
{
    Y[0] = X[1];
    Y[1] = X[2];
    Y[2] = X[3]    ^ X[4]>>3;
    Y[3] = X[4];
    Y[4] = X[5]    ^ X[6]<<3;
    Y[5] = X[3]<<2 ^ X[6];
    Y[6] = X[7];
    Y[7] = X[0];
}

#if LANES_NB >= 6
static void _multiply_MR2(const uint8_t X[LANE_BYTES], uint8_t Y[LANE_BYTES])
{
    uint8_t x14 = X[5] ^ X[6]<<3;

    Y[0] = X[2];
    Y[1] = X[3]    ^ X[4]>>3;
    Y[2] = X[4]    ^ x14>>3;
    Y[3] = x14;
    Y[4] = X[3]<<2 ^ X[6]    ^ X[7]<<3;
    Y[5] = X[4]<<2 ^ X[7];
    Y[6] = X[0];
    Y[7] = X[1];
}

#if LANES_NB >= 7
static void _multiply_MR3(const uint8_t X[LANE_BYTES], uint8_t Y[LANE_BYTES])
{
    uint8_t x14 = X[5]    ^ X[6]<<3;
    uint8_t x24 = X[3]<<2 ^ X[6]    ^ X[7]<<3 ;

    Y[0] = X[3]    ^ X[4]>>3;
    Y[1] = X[4]    ^ x14>>3;
    Y[2] = x14     ^ x24>>3;
    Y[3] = x24;
    Y[4] = X[4]<<2 ^ X[7] ^ X[0]<<3;
    Y[5] = x14<<2  ^ X[0];
    Y[6] = X[1];
    Y[7] = X[2];
}
#endif
#endif
#endif


#define TWEAK_LANES (TWEAK_BYTES/LANE_BYTES)
#define KEY_LANES   (KEY_BYTES/LANE_BYTES)

void tweakey_state_update(uint8_t TK_X[TWEAKEY_BYTES], uint8_t TK_Y[KEY_BYTES])
{
    /* Skip lane 0, as it is multiplied by the identity matrix. */

    size_t j;
    uint8_t *TKj_X;
    uint8_t *TKj_Y;
    RAM_DATA_BYTE TKj_old_X[LANE_BYTES];
    RAM_DATA_BYTE TKj_old_Y[LANE_BYTES];

    j = 1;
    TKj_X = TK_X + j*LANE_BYTES;
    memcpy(TKj_old_X, TKj_X, LANE_BYTES);
    _multiply_M(TKj_old_X, TKj_X);

#if TWEAK_LANES == 2
    j = 0;
    TKj_X = TK_X + (j+TWEAK_LANES)*LANE_BYTES;
    TKj_Y = TK_Y + j*LANE_BYTES;
    memcpy(TKj_old_X, TKj_X, LANE_BYTES);
    memcpy(TKj_old_Y, TKj_Y, LANE_BYTES);
    _multiply_M2(TKj_old_X, TKj_X);
    _multiply_M2(TKj_old_Y, TKj_Y);

    j = 1;
    TKj_X = TK_X + (j+TWEAK_LANES)*LANE_BYTES;
    TKj_Y = TK_Y + j*LANE_BYTES;
    memcpy(TKj_old_X, TKj_X, LANE_BYTES);
    memcpy(TKj_old_Y, TKj_Y, LANE_BYTES);
    _multiply_M3(TKj_old_X, TKj_X);
    _multiply_M3(TKj_old_Y, TKj_Y);

  #if LANES_NB >= 5
    j = 2;
    TKj_X = TK_X + (j+TWEAK_LANES)*LANE_BYTES;
    TKj_Y = TK_Y + j*LANE_BYTES;
    memcpy(TKj_old_X, TKj_X, LANE_BYTES);
    memcpy(TKj_old_Y, TKj_Y, LANE_BYTES);
    _multiply_MR(TKj_old_X, TKj_X);
    _multiply_MR(TKj_old_Y, TKj_Y);

  #if LANES_NB >= 6
    j = 3;
    TKj_X = TK_X + (j+TWEAK_LANES)*LANE_BYTES;
    TKj_Y = TK_Y + j*LANE_BYTES;
    memcpy(TKj_old_X, TKj_X, LANE_BYTES);
    memcpy(TKj_old_Y, TKj_Y, LANE_BYTES);
    _multiply_MR2(TKj_old_X, TKj_X);
    _multiply_MR2(TKj_old_Y, TKj_Y);
  #endif
  #endif

#else  /* TWEAK_LANES == 3 */
    j = 2;
    TKj_X = TK_X + j*LANE_BYTES;
    memcpy(TKj_old_X, TKj_X, LANE_BYTES);
    _multiply_M2(TKj_old_X, TKj_X);

    j = 0;
    TKj_X = TK_X + (j+TWEAK_LANES)*LANE_BYTES;
    TKj_Y = TK_Y + j*LANE_BYTES;
    memcpy(TKj_old_X, TKj_X, LANE_BYTES);
    memcpy(TKj_old_Y, TKj_Y, LANE_BYTES);
    _multiply_M3(TKj_old_X, TKj_X);
    _multiply_M3(TKj_old_Y, TKj_Y);

  #if LANES_NB >= 5
    j = 1;
    TKj_X = TK_X + (j+TWEAK_LANES)*LANE_BYTES;
    TKj_Y = TK_Y + j*LANE_BYTES;
    memcpy(TKj_old_X, TKj_X, LANE_BYTES);
    memcpy(TKj_old_Y, TKj_Y, LANE_BYTES);
    _multiply_MR(TKj_old_X, TKj_X);
    _multiply_MR(TKj_old_Y, TKj_Y);

  #if LANES_NB >= 6
    j = 2;
    TKj_X = TK_X + (j+TWEAK_LANES)*LANE_BYTES;
    TKj_Y = TK_Y + j*LANE_BYTES;
    memcpy(TKj_old_X, TKj_X, LANE_BYTES);
    memcpy(TKj_old_Y, TKj_Y, LANE_BYTES);
    _multiply_MR2(TKj_old_X, TKj_X);
    _multiply_MR2(TKj_old_Y, TKj_Y);

  #if LANES_NB >= 7
    j = 3;
    TKj_X = TK_X + (j+TWEAK_LANES)*LANE_BYTES;
    TKj_Y = TK_Y + j*LANE_BYTES;
    memcpy(TKj_old_X, TKj_X, LANE_BYTES);
    memcpy(TKj_old_Y, TKj_Y, LANE_BYTES);
    _multiply_MR3(TKj_old_X, TKj_X);
    _multiply_MR3(TKj_old_Y, TKj_Y);
  #endif
  #endif
  #endif

#endif
}
