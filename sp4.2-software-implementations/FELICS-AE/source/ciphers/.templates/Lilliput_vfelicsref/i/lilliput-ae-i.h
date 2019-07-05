#ifndef LILLIPUT_AE_I_H
#define LILLIPUT_AE_I_H

#include "ae-common.h"
#include "tbc.h"


static const uint8_t _0n[BLOCK_BYTES] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


static inline uint8_t _upper_nibble(uint8_t i)
{
    return i >> 4;
}

static inline uint8_t _lower_nibble(uint8_t i)
{
    return i & 0x0f;
}

static void _init_msg_tweak(const uint8_t N[NONCE_BYTES], uint8_t tweak[TWEAK_BYTES])
{
    /* The t-bit tweak is filled as follows:
     *
     *   1    4    5     |N|+4    |N|+5     t
     * [ prefix ||  nonce      || block index ]
     *
     * The s-bit block index is encoded as follows:
     *
     *   |N|+5    t-s    t-s+1                t
     * [ zero padding || block index, MSB first ]
     *
     * This function sets bits 5 to t-s once and for all.
     */

    tweak[0] = _upper_nibble(N[0]);

    for (size_t i=1; i<NONCE_BYTES; i++)
    {
        tweak[i] = _lower_nibble(N[i-1]) << 4 ^ _upper_nibble(N[i]);
    }

    tweak[NONCE_BYTES] = _lower_nibble(N[NONCE_BYTES-1]) << 4;

    /* The number of bits we need to zero out is:
     *     t - |N| - s - 4        - 4
     *                   (prefix)   (zeroed out by previous assignment)
     */
    memset(&tweak[NONCE_BYTES+1], 0, TWEAK_BYTES-NONCE_BYTES-sizeof(size_t)-1);
}

static void _fill_msg_tweak(
    uint8_t prefix,
    size_t  block_index,
    uint8_t tweak[TWEAK_BYTES]
)
{
    /* The t-bit tweak is filled as follows:
     *
     *   1    4    5     |N|+4    |N|+5     t
     * [ prefix ||  nonce      || block index ]
     *
     * The s-bit block index is encoded as follows:
     *
     *   |N|+5    t-s    t-s+1                t
     * [ zero padding || block index, MSB first ]
     *
     * This function assumes bits 5 to t-s have already been set, and
     * only sets bits 1 to 4 and t-s+1 to t.
     */

    uint8_t *msb = &tweak[0];
    *msb = prefix<<4 ^ _lower_nibble(*msb);

    copy_block_index(block_index, tweak);
}

static void _generate_tag(
    const uint8_t Final[BLOCK_BYTES],
    const uint8_t Auth[BLOCK_BYTES],
    uint8_t       tag[TAG_BYTES]
)
{
    xor_arrays(TAG_BYTES, tag, Final, Auth);
}

#endif /* LILLIPUT_AE_I_H */
