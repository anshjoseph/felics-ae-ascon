/*
Implementation of the Lilliput-AE tweakable block cipher.

Authors, hereby denoted as "the implementer":
    Kévin Le Gouguec,
    2019.

For more information, feedback or questions, refer to our website:
https://paclido.fr/lilliput-ae

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

This file implements Lilliput-AE's nonce-respecting mode based on ΘCB3.
*/

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "lilliput-ae-i.h"
#include "cipher.h"


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

    RAM_DATA_BYTE tweak[TWEAK_BYTES];
    _init_msg_tweak(N, tweak);

    RAM_DATA_BYTE checksum[BLOCK_BYTES];
    memset(checksum, 0, BLOCK_BYTES);

    for (size_t j=0; j<l; j++)
    {
        xor_into(checksum, &M[j*BLOCK_BYTES]);
        _fill_msg_tweak(0x0, j, tweak);
        encrypt(key, tweak, &M[j*BLOCK_BYTES], &C[j*BLOCK_BYTES]);
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

        pad10(rest, &M[l*BLOCK_BYTES], M_rest);
        xor_into(checksum, M_rest);

        _fill_msg_tweak(0x4, l, tweak);
        encrypt(key, tweak, _0n, Pad);
        xor_arrays(rest, &C[l*BLOCK_BYTES], &M[l*BLOCK_BYTES], Pad);

        _fill_msg_tweak(0x5, l+1, tweak);
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
    RAM_DATA_BYTE auth[BLOCK_BYTES];
    process_associated_data(key, auth_data_len, auth_data, auth);

    RAM_DATA_BYTE final[BLOCK_BYTES];
    _encrypt_message(key, message_len, message, nonce, ciphertext, final);

    _generate_tag(final, auth, tag);
}

int crypto_aead_encrypt(
	uint8_t *c, size_t *clen,
	const uint8_t *m, size_t mlen,
	const uint8_t *ad, size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
)
{
    _lilliput_ae_encrypt(mlen, m, adlen, ad, k, npub, c, c+mlen);
    *clen = mlen + TAG_BYTES;

    return 0;
}
