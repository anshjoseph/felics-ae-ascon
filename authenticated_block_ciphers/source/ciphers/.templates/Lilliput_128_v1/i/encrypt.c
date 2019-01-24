#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "lilliput-ae-i.h"
#include "tbc.h"


static void _encrypt_message(
    const uint8_t key[KEY_BYTES],
    size_t        M_len,
    const uint8_t M[M_len],
    const uint8_t N[NONCE_BYTES],
    uint8_t       C[M_len+BLOCK_BYTES],
    uint8_t       Final[BLOCK_BYTES]
)
{
    size_t l = M_len / BLOCK_BYTES;
    size_t rest = M_len % BLOCK_BYTES;

    uint8_t tweak[TWEAK_BYTES];
    uint8_t checksum[BLOCK_BYTES];

    memset(tweak, 0, TWEAK_BYTES);
    memset(checksum, 0, BLOCK_BYTES);

    for (size_t j=0; j<l; j++)
    {
        xor_into(checksum, &M[j*BLOCK_BYTES]);
        _fill_msg_tweak(0x0, N, j, tweak);
        encrypt(key, tweak, &M[j*BLOCK_BYTES], &C[j*BLOCK_BYTES]);
    }

    if (rest == 0)
    {
        _fill_msg_tweak(0x1, N, l-1, tweak);
        encrypt(key, tweak, checksum, Final);
    }
    else
    {
        uint8_t M_rest[BLOCK_BYTES];
        uint8_t Pad[BLOCK_BYTES];

        pad10(rest, &M[l*BLOCK_BYTES], M_rest);
        xor_into(checksum, M_rest);

        _fill_msg_tweak(0x4, N, l, tweak);
        encrypt(key, tweak, _0n, Pad);
        xor_arrays(rest, &C[l*BLOCK_BYTES], &M[l*BLOCK_BYTES], Pad);

        _fill_msg_tweak(0x5, N, l, tweak);
        encrypt(key, tweak, checksum, Final);
    }
}

static void _lilliput_ae_encrypt(
    size_t        message_len,
    const uint8_t message[message_len],
    size_t        auth_data_len,
    const uint8_t auth_data[auth_data_len],
    const uint8_t key[KEY_BYTES],
    const uint8_t nonce[NONCE_BYTES],
    uint8_t       ciphertext[message_len],
    uint8_t       tag[TAG_BYTES]
)
{
    uint8_t auth[BLOCK_BYTES];
    process_associated_data(key, auth_data_len, auth_data, auth);

    uint8_t final[BLOCK_BYTES];
    _encrypt_message(key, message_len, message, nonce, ciphertext, final);

    _generate_tag(final, auth, tag);
}

void Encrypt(uint8_t *block, size_t mlen, uint8_t *key, uint8_t *npub,
             uint8_t *ad, size_t adlen, uint8_t *c, uint8_t *roundKeys)
{
    _lilliput_ae_encrypt(mlen, block, adlen, ad, key, npub, c, c+mlen);
}
