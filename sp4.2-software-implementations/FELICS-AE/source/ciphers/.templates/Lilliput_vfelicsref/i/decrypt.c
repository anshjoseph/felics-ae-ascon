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

    RAM_DATA_BYTE tweak[TWEAK_BYTES];
    _init_msg_tweak(N, tweak);

    RAM_DATA_BYTE checksum[BLOCK_BYTES];
    memset(checksum, 0, BLOCK_BYTES);

    for (size_t j=0; j<l; j++)
    {
        _fill_msg_tweak(0x0, j, tweak);
        decrypt(key, tweak, &C[j*BLOCK_BYTES], &M[j*BLOCK_BYTES]);
        xor_into(checksum, &M[j*BLOCK_BYTES]);
    }

    if (rest == 0)
    {
        _fill_msg_tweak(0x1, l, tweak);
        encrypt(key, tweak, checksum, Final);
    }
    else
    {
        RAM_DATA_BYTE M_rest[BLOCK_BYTES];
        RAM_DATA_BYTE Pad[BLOCK_BYTES];

        _fill_msg_tweak(0x4, l, tweak);
        encrypt(key, tweak, _0n, Pad);
        xor_arrays(rest, &M[l*BLOCK_BYTES], &C[l*BLOCK_BYTES], Pad);

        pad10(rest, &M[l*BLOCK_BYTES], M_rest);
        xor_into(checksum, M_rest);

        _fill_msg_tweak(0x5, l+1, tweak);
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
    RAM_DATA_BYTE auth[BLOCK_BYTES];
    process_associated_data(key, auth_data_len, auth_data, auth);

    RAM_DATA_BYTE final[BLOCK_BYTES];
    _decrypt_message(key, ciphertext_len, ciphertext, nonce, message, final);

    RAM_DATA_BYTE effective_tag[TAG_BYTES];
    _generate_tag(final, auth, effective_tag);

    return memcmp(tag, effective_tag, TAG_BYTES) == 0;
}

int crypto_aead_decrypt(
	uint8_t *m, size_t *mlen,
	const uint8_t *c, size_t clen,
	const uint8_t *ad, size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
)
{
    size_t tagless_len = clen-TAG_BYTES;

    bool valid = _lilliput_ae_decrypt(
        tagless_len, c, adlen, ad, k, npub, c+tagless_len, m
    );

    if (!valid)
        return -1;

    *mlen = tagless_len;

    return 0;
}
