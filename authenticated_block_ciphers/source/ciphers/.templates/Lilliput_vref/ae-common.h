#ifndef AE_COMMON_H
#define AE_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "tbc.h"
#include "parameters.h"


static inline uint8_t upper_nibble(uint8_t i)
{
    return i >> 4;
}

static inline uint8_t lower_nibble(uint8_t i)
{
    return i & 0x0f;
}

static inline void encrypt(const uint8_t K[KEY_BYTES],
                           const uint8_t T[TWEAK_BYTES],
                           const uint8_t M[BLOCK_BYTES],
                           uint8_t C[BLOCK_BYTES])
{
    lilliput_tbc_encrypt(K, T, M, C);
}

static inline void decrypt(const uint8_t K[KEY_BYTES],
                           const uint8_t T[TWEAK_BYTES],
                           const uint8_t C[BLOCK_BYTES],
                           uint8_t M[BLOCK_BYTES])
{
    lilliput_tbc_decrypt(K, T, C, M);
}

static inline void xor_into(uint8_t dest[BLOCK_BYTES], const uint8_t src[BLOCK_BYTES])
{
    for (size_t i=0; i<BLOCK_BYTES; i++)
        dest[i] ^= src[i];
}

static inline void xor_arrays(size_t len, uint8_t out[len], const uint8_t a[len], const uint8_t b[len])
{
    for (size_t i=0; i<len; i++)
        out[i] = a[i] ^ b[i];
}

static inline void pad10(size_t X_len, const uint8_t X[X_len], uint8_t padded[BLOCK_BYTES])
{
    /* pad10*(X) = X || 1 || 0^{n-|X|-1} */

    /* Assume that len<BLOCK_BYTES. */

    size_t pad_len = BLOCK_BYTES-X_len;

    memcpy(padded+pad_len, X, X_len);

    padded[pad_len-1] = 0x80;

    if (pad_len > 1)
    {
        memset(padded, 0, pad_len-1);
    }
}

static inline void fill_index_tweak(
    uint8_t  prefix,
    uint64_t block_index,
    uint8_t  tweak[TWEAK_BYTES]
)
{
    /* The t-bit tweak is filled as follows:
     *
     * - bits [  1, t-4]: block index
     *        [  1,  64]: actual 64-bit block index
     *        [ 65, t-4]: 0-padding
     * - bits [t-3,   t]: constant 4-bit prefix
     */

    for (size_t i=0; i<sizeof(block_index); i++)
    {
        tweak[i] = block_index >> 8*i & 0xff;
    }

    /* Assume padding bytes have already been memset to 0. */

    tweak[TWEAK_BYTES-1] |= prefix << 4;
}

static void process_associated_data(
    const uint8_t key[KEY_BYTES],
    size_t        A_len,
    const uint8_t A[A_len],
    uint8_t       Auth[BLOCK_BYTES]
)
{
    uint8_t Ek_Ai[BLOCK_BYTES];
    uint8_t tweak[TWEAK_BYTES];

    memset(tweak, 0, TWEAK_BYTES);
    memset(Auth, 0, BLOCK_BYTES);

    size_t l_a = A_len / BLOCK_BYTES;
    size_t rest = A_len % BLOCK_BYTES;

    for (size_t i=0; i<l_a; i++)
    {
        fill_index_tweak(0x2, i, tweak);
        encrypt(key, tweak, &A[i*BLOCK_BYTES], Ek_Ai);
        xor_into(Auth, Ek_Ai);
    }

    if (rest != 0)
    {
        uint8_t A_rest[BLOCK_BYTES];
        pad10(rest, &A[l_a*BLOCK_BYTES], A_rest);
        fill_index_tweak(0x6, l_a, tweak);
        encrypt(key, tweak, A_rest, Ek_Ai);
        xor_into(Auth, Ek_Ai);
    }
}



#endif /* AE_COMMON_H */
