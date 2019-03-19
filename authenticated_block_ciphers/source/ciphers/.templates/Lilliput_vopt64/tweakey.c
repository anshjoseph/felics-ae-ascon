#include <stdint.h>
#include <string.h>

#include "parameters.h"
#include "tweakey.h"


void tweakey_state_init(
    uint64_t TK[LANES_NB],
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES]
)
{
    void *TK_buffer = TK;
    memcpy(TK_buffer,             tweak, TWEAK_BYTES);
    memcpy(TK_buffer+TWEAK_BYTES, key,   KEY_BYTES);
}




static uint8_t _nth_byte(uint64_t x, size_t n)
{
    return x >> n*8;
}

void tweakey_state_extract(
    const uint64_t TK[LANES_NB],
    uint8_t round_constant,
    uint8_t round_tweakey[ROUND_TWEAKEY_BYTES]
)
{
    memset(round_tweakey, 0, ROUND_TWEAKEY_BYTES);

    for (size_t j=0; j<LANES_NB; j++)
    {
        for (size_t k=0; k<LANE_BYTES; k++)
        {
            round_tweakey[k] ^= _nth_byte(TK[j], k);
        }
    }

    round_tweakey[0] ^= round_constant;
}


static uint64_t _rotl64(uint64_t x, size_t n)
{
    return x<<n | x>>(64-n);
}

static uint64_t _rotr64(uint64_t x, size_t n)
{
    return x>>n | x<<(64-n);
}

static uint64_t _shl_permute(uint64_t x, size_t dest, size_t src, size_t shift)
{
    uint8_t x_src_shifted = _nth_byte(x, src) << shift;
    return (uint64_t)x_src_shifted << 8*dest;
}

static uint64_t _shr_permute(uint64_t x, size_t dest, size_t src, size_t shift)
{
    uint8_t x_src_shifted = _nth_byte(x, src) >> shift;
    return (uint64_t)x_src_shifted << 8*dest;
}

static uint64_t _multiply_M(uint64_t x)
{
    uint64_t y = _rotl64(x, 8);

    y ^= _shl_permute(x, 5, 5, 3);
    y ^= _shr_permute(x, 4, 4, 3);
    y ^= _shl_permute(x, 2, 6, 2);

    return y;
}

static uint64_t _multiply_M2(uint64_t x)
{
    return _multiply_M(_multiply_M(x));
}

static uint64_t _multiply_M3(uint64_t x)
{
    return _multiply_M(_multiply_M(_multiply_M(x)));
}

#if LANES_NB >= 5
static uint64_t _multiply_MR(uint64_t x)
{
    uint64_t y = _rotr64(x, 8);

    y ^= _shr_permute(x, 2, 4, 3);
    y ^= _shl_permute(x, 4, 6, 3);
    y ^= _shl_permute(x, 5, 3, 2);

    return y;
}

#if LANES_NB >= 6
static uint64_t _multiply_MR2(uint64_t x)
{
    return _multiply_MR(_multiply_MR(x));
}

#if LANES_NB >= 7
static uint64_t _multiply_MR3(uint64_t x)
{
    return _multiply_MR(_multiply_MR(_multiply_MR(x)));
}
#endif
#endif
#endif

typedef uint64_t (*matrix_multiplication)(uint64_t x);

static const matrix_multiplication ALPHAS[6] = {
    _multiply_M,
    _multiply_M2,
    _multiply_M3,
#if LANES_NB >= 5
    _multiply_MR,
#if LANES_NB >= 6
    _multiply_MR2,
#if LANES_NB >= 7
    _multiply_MR3
#endif
#endif
#endif
};


void tweakey_state_update(uint64_t TK[LANES_NB])
{
    /* Skip lane 0, as it is multiplied by the identity matrix. */

    for (size_t j=1; j<LANES_NB; j++)
    {
        TK[j] = ALPHAS[j-1](TK[j]);
    }
}
