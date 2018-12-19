#ifndef LILLIPUT_AE_II_H
#define LILLIPUT_AE_II_H

#include "ae-common.h"
#include "tbc.h"


static void _init_msg_tweak(const uint8_t tag[TAG_BYTES], uint8_t tweak[TWEAK_BYTES])
{
    /* The t-bit tweak is filled as follows:
     *
     * - bits [  1, t-1]: tag + block index
     *        [  1,  64]: tag[ 1.. 64] XOR block index
     *        [ 65, t-1]: tag[65..t-1]
     * - bit t: 1
     */

    memcpy(tweak+sizeof(uint64_t), tag+sizeof(uint64_t), TAG_BYTES-sizeof(uint64_t));
    tweak[TWEAK_BYTES-1] |= 0x80;
}

static void _fill_msg_tweak(const uint8_t tag[TAG_BYTES], uint64_t block_index, uint8_t tweak[TWEAK_BYTES])
{
    /* Assume bits 65 to t-1 are set. */
    for (size_t i=0; i<sizeof(block_index); i++)
    {
        uint8_t index_i = block_index >> i*8 & 0xff;
        tweak[i] = tag[i] ^ index_i;
    }
}

static void _fill_tag_tweak(const uint8_t N[NONCE_BYTES], uint8_t tweak[TWEAK_BYTES])
{
    /* The t-bit tweak is filled as follows:
     *
     * - bits [  1, t-7]: N
     * - bits [t-7,   t]: 0001||0^4
     */

    memcpy(tweak, N, TWEAK_BYTES-1);
    tweak[TWEAK_BYTES-1] = 0x10;
}

static void _generate_tag(
    const uint8_t key[KEY_BYTES],
    size_t        M_len,
    const uint8_t M[M_len],
    const uint8_t N[NONCE_BYTES],
    const uint8_t Auth[BLOCK_BYTES],
    uint8_t       tag[TAG_BYTES]
)
{
    uint8_t Ek_Mj[BLOCK_BYTES];
    uint8_t tag_tmp[TAG_BYTES];
    uint8_t tweak[TWEAK_BYTES];

    memset(tweak, 0, TWEAK_BYTES);
    memcpy(tag_tmp, Auth, TAG_BYTES);

    size_t l = M_len / BLOCK_BYTES;
    size_t rest = M_len % BLOCK_BYTES;

    for (size_t j=0; j<l; j++)
    {
        fill_index_tweak(0x0, j, tweak);
        encrypt(key, tweak, &M[j*BLOCK_BYTES], Ek_Mj);
        xor_into(tag_tmp, Ek_Mj);
    }

    if (rest != 0)
    {
        uint8_t M_rest[BLOCK_BYTES];
        pad10(rest, &M[l*BLOCK_BYTES], M_rest);
        fill_index_tweak(0x4, l, tweak);
        encrypt(key, tweak, M_rest, Ek_Mj);
        xor_into(tag_tmp, Ek_Mj);
    }

    _fill_tag_tweak(N, tweak);
    encrypt(key, tweak, tag_tmp, tag);
}

static void _encrypt_message(
    const uint8_t key[KEY_BYTES],
    size_t        M_len,
    const uint8_t M[M_len],
    const uint8_t N[NONCE_BYTES],
    const uint8_t tag[TAG_BYTES],
    uint8_t       C[M_len]
)
{
    uint8_t Ek_N[BLOCK_BYTES];

    uint8_t tweak[TWEAK_BYTES];
    _init_msg_tweak(tag, tweak);

    uint8_t padded_N[BLOCK_BYTES];
    memcpy(padded_N, N, NONCE_BYTES);
    padded_N[BLOCK_BYTES-1] = 0;

    size_t l = M_len / BLOCK_BYTES;
    size_t rest = M_len % BLOCK_BYTES;

    for (size_t j=0; j<l; j++)
    {
        _fill_msg_tweak(tag, j, tweak);
        encrypt(key, tweak, padded_N, Ek_N);
        xor_arrays(BLOCK_BYTES, &C[j*BLOCK_BYTES], &M[j*BLOCK_BYTES], Ek_N);
    }

    if (rest != 0)
    {
        _fill_msg_tweak(tag, l, tweak);
        encrypt(key, tweak, padded_N, Ek_N);
        xor_arrays(rest, &C[l*BLOCK_BYTES], &M[l*BLOCK_BYTES], Ek_N);
    }
}



#endif /* LILLIPUT_AE_II_H */
