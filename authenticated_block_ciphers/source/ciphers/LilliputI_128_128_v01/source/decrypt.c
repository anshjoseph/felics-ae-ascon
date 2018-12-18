#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "lilliput-ae-i.h"
#include "tbc.h"


static void _decrypt_message(
    const uint8_t key[KEY_BYTES],
    size_t        C_len,
    const uint8_t C[C_len],
    const uint8_t N[NONCE_BYTES],
    uint8_t       M[C_len],
    uint8_t       Final[BLOCK_BYTES]
)
{
    size_t l = C_len / BLOCK_BYTES;
    size_t rest = C_len % BLOCK_BYTES;

    uint8_t tweak[TWEAK_BYTES];
    uint8_t checksum[BLOCK_BYTES];

    memset(tweak, 0, TWEAK_BYTES);
    memset(checksum, 0, BLOCK_BYTES);

    for (size_t j=0; j<l; j++)
    {
        _fill_msg_tweak(0x0, N, j, tweak);
        decrypt(key, tweak, &C[j*BLOCK_BYTES], &M[j*BLOCK_BYTES]);
        xor_into(checksum, &M[j*BLOCK_BYTES]);
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

        _fill_msg_tweak(0x4, N, l, tweak);
        encrypt(key, tweak, _0n, Pad);
        xor_arrays(rest, &M[l*BLOCK_BYTES], &C[l*BLOCK_BYTES], Pad);

        pad10(rest, &M[l*BLOCK_BYTES], M_rest);
        xor_into(checksum, M_rest);

        _fill_msg_tweak(0x5, N, l, tweak);
        encrypt(key, tweak, checksum, Final);
    }
}

static bool _lilliput_ae_decrypt(
    size_t        ciphertext_len,
    const uint8_t ciphertext[ciphertext_len],
    size_t        auth_data_len,
    const uint8_t auth_data[auth_data_len],
    const uint8_t key[KEY_BYTES],
    const uint8_t nonce[NONCE_BYTES],
    const uint8_t tag[TAG_BYTES],
    uint8_t       message[ciphertext_len]
)
{
    uint8_t auth[BLOCK_BYTES];
    process_associated_data(key, auth_data_len, auth_data, auth);

    uint8_t final[BLOCK_BYTES];
    _decrypt_message(key, ciphertext_len, ciphertext, nonce, message, final);

    uint8_t effective_tag[TAG_BYTES];
    _generate_tag(final, auth, effective_tag);

    return memcmp(tag, effective_tag, TAG_BYTES) == 0;
}

uint8_t Decrypt(uint8_t *block, int32_t mlen, uint8_t *key, uint8_t *npub,
                uint8_t *ad, int32_t adlen, uint8_t *c, uint8_t *roundKeys)
{
    return _lilliput_ae_decrypt(mlen, c, adlen, ad, key, npub, c+mlen, block)
        ? 0 : -1;
}
