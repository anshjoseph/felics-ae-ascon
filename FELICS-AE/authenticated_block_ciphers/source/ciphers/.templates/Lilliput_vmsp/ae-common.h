#ifndef AE_COMMON_H
#define AE_COMMON_H

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "tweak-formatting functions assume little-endian byte order."
#endif

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
    __asm__ volatile (
        "xor 0(%[src]), 0(%[dest])" "\n\t"
        "xor 2(%[src]), 2(%[dest])" "\n\t"
        "xor 4(%[src]), 4(%[dest])" "\n\t"
        "xor 6(%[src]), 6(%[dest])" "\n\t"
        "xor 8(%[src]), 8(%[dest])" "\n\t"
        "xor 10(%[src]), 10(%[dest])" "\n\t"
        "xor 12(%[src]), 12(%[dest])" "\n\t"
        "xor 14(%[src]), 14(%[dest])" "\n\t"
        :
        : [dest] "p" (dest), [src] "p" (src)
        : "memory"
    );
}

static inline void xor_arrays(size_t len, uint8_t out[len], const uint8_t a[len], const uint8_t b[len])
{
    for (size_t i=0; i<len; i++)
        out[i] = a[i] ^ b[i];
}

static inline void pad10(size_t X_len, const uint8_t X[X_len], uint8_t padded[BLOCK_BYTES])
{
    /* pad10*(X) = X || 1 || 0^{n-|X|-1} */

    /* For example, with uint8_t X[3] = { [0]=0x01, [1]=0x02, [2]=0x03 }
     *
     * pad10*(X) =
     *       X[2]     X[1]     X[0]   1 0*
     *     00000011 00000010 00000001 1 0000000 00000000...
     *
     * - padded[0, 11]:  zeroes
     * - padded[12]:     10000000
     * - padded[13, 15]: X[0, 2]
     */

    /* Assume that X_len<BLOCK_BYTES. */

    size_t pad_len = BLOCK_BYTES-X_len;

    memset(padded, 0, pad_len-1);
    padded[pad_len-1] = 0x80;
    memcpy(padded+pad_len, X, X_len);
}

static inline void copy_block_index(size_t index, uint8_t tweak[TWEAK_BYTES])
{
    __asm__ volatile (
        "mov %[index], @%[tweak]" "\n\t"
        :
        : [index] "r" (index), [tweak] "p" (tweak)
        : "memory"
    );
}

static inline void fill_index_tweak(
    uint8_t prefix,
    size_t  block_index,
    uint8_t tweak[TWEAK_BYTES]
)
{
    /* With an s-bit block index, the t-bit tweak is filled as follows:
     *
     * - bits [  1, t-4]: block index
     *        [  1,   s]: actual block index
     *        [s+1, t-4]: 0-padding
     * - bits [t-3,   t]: 4-bit prefix
     */

    copy_block_index(block_index, tweak);

    /* Assume padding bytes have already been set to 0. */

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
