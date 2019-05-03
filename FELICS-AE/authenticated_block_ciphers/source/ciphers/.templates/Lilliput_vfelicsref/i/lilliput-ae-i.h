#ifndef LILLIPUT_AE_I_H
#define LILLIPUT_AE_I_H

#include "ae-common.h"
#include "tbc.h"


static const uint8_t _0n[BLOCK_BYTES] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static void _init_msg_tweak(const uint8_t N[NONCE_BYTES], uint8_t tweak[TWEAK_BYTES])
{
    /* With an s-bit block index, the t-bit tweak is filled as follows:
     *
     * - bits [      1, t-|N|-4]: block index
     *        [      1,       s]: actual block index
     *        [    s+1, t-|N|-4]: 0-padding
     * - bits [t-|N|-3,     t-4]: nonce
     * - bits [    t-3,       t]: 4-bit prefix
     *
     * This function sets bits s+1 to t-4 once and for all.
     */

    size_t N_start = TWEAK_BYTES - NONCE_BYTES - 1;

    for (size_t i=sizeof(size_t); i<N_start; i++)
    {
        tweak[i] = 0;
    }

    tweak[N_start] = lower_nibble(N[0]) << 4;

    for (size_t i=1; i<NONCE_BYTES; i++)
    {
        tweak[N_start+i] = lower_nibble(N[i]) << 4 ^ upper_nibble(N[i-1]);
    }

    tweak[TWEAK_BYTES-1] = upper_nibble(N[NONCE_BYTES-1]);
}

static void _fill_msg_tweak(
    uint8_t       prefix,
    size_t        block_index,
    uint8_t       tweak[TWEAK_BYTES]
)
{
    /* With an s-bit block index, the t-bit tweak is filled as follows:
     *
     * - bits [      1, t-|N|-4]: block index
     *        [      1,       s]: actual block index
     *        [    s+1, t-|N|-4]: 0-padding
     * - bits [t-|N|-3,     t-4]: nonce
     * - bits [    t-3,       t]: 4-bit prefix
     *
     * This function assumes bits s+1 to t-3 have already been set,
     * and only sets bits 1 to s and t-3 to t.
     */

    copy_block_index(block_index, tweak);

    uint8_t *msb = &tweak[TWEAK_BYTES-1];
    *msb = prefix<<4 ^ lower_nibble(*msb);

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
