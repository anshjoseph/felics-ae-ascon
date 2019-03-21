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
    uint64_t      block_nb,
    uint8_t       tweak[TWEAK_BYTES]
)
{
    /* The 192-bit tweak is filled as follows:
     *
     * - bits   1- 68: block number
     *          1- 64: actual 64-bit block number
     *         64- 68: 0-padding
     * - bits  67-188: nonce
     * - bits 189-192: constant 4-bit prefix
     */

    for (size_t i=0; i<sizeof(block_nb); i++)
    {
        uint64_t mask = (uint64_t)0xff << 8*i;
        uint8_t b = (mask & block_nb) >> 8*i;

        tweak[i] = b;
    }

    tweak[sizeof(block_nb)] = lower_nibble(N[0]) << 4;

    for (size_t i=1; i<NONCE_BYTES; i++)
    {
        tweak[sizeof(block_nb)+i] = lower_nibble(N[i]) << 4 ^ upper_nibble(N[i-1]);
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
