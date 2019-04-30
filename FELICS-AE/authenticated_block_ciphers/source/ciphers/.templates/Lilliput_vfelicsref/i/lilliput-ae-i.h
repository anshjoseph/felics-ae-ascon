#ifndef LILLIPUT_AE_I_H
#define LILLIPUT_AE_I_H

#include "ae-common.h"
#include "tbc.h"


static const uint8_t _0n[BLOCK_BYTES] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static void _fill_msg_tweak(
    uint8_t       prefix,
    const uint8_t N[NONCE_BYTES],
    size_t        block_index,
    uint8_t       tweak[TWEAK_BYTES]
)
{
    /* With an s-bit block index, the t-bit tweak is filled as follows:
     *
     * - bits [      1, t-|N|-4]: block index
     *        [      1,       s]: actual 64-bit block index
     *        [    s+1, t-|N|-4]: 0-padding
     * - bits [t-|N|-4,     t-4]: nonce
     * - bits [    t-3,       t]: 4-bit prefix
     */

    copy_block_index(block_index, tweak);

    tweak[sizeof(block_index)] = lower_nibble(N[0]) << 4;

    for (size_t i=1; i<NONCE_BYTES; i++)
    {
        tweak[sizeof(block_index)+i] = lower_nibble(N[i]) << 4 ^ upper_nibble(N[i-1]);
    }

    tweak[TWEAK_BYTES-1] = prefix << 4 ^ upper_nibble(N[NONCE_BYTES-1]);
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
