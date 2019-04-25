#include <stdint.h>
#include <string.h>

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


#define NEWLINE "\n\t"

static void _multiply_M(const uint8_t X[LANE_BYTES], uint8_t Y[LANE_BYTES])
{
    __asm__ volatile (
        "mov.b 4(%[X]), r4" NEWLINE
        "mov.b 5(%[X]), r5" NEWLINE
        "mov.b 6(%[X]), r6" NEWLINE

        "mov.b 2(%[X]), 3(%[Y])" NEWLINE
        "mov.b 0(%[X]), 1(%[Y])" NEWLINE
        "mov.b 7(%[X]), 0(%[Y])" NEWLINE

        /* send x6 to y7 */
        "mov.b r6, 7(%[Y])" NEWLINE
        /* now compute y2 from x6 and x1 */
        "rla.b r6" NEWLINE
        "rla.b r6" NEWLINE
        "xor.b 1(%[X]), r6" NEWLINE
        "mov.b r6, 2(%[Y])" NEWLINE

        /* send x5 to y6 */
        "mov.b r5, 6(%[Y])" NEWLINE
        /* now compute y5 from x5 and x4 */
        "rla.b r5" NEWLINE
        "rla.b r5" NEWLINE
        "rla.b r5" NEWLINE
        "xor.b r4, r5" NEWLINE
        "mov.b r5, 5(%[Y])" NEWLINE

        /* compute y4 from x4 and x3 */
        "rra.b r4" NEWLINE
        "rra.b r4" NEWLINE
        "rra.b r4" NEWLINE
        "xor.b 3(%[X]), r4" NEWLINE
        "mov.b r4, 4(%[Y])" NEWLINE

        : [Y] "=r" (Y)
        : [X] "r" (X)
        : "R4", "R5", "R6"
    );
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


void tweakey_state_update(uint8_t TK[TWEAKEY_BYTES])
{
    /* Skip lane 0, as it is multiplied by the identity matrix. */

    size_t j;
    uint8_t *TKj;
    uint8_t TKj_old[LANE_BYTES];

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
