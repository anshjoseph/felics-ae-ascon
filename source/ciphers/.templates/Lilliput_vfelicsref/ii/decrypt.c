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

This file implements Lilliput-AE's nonce-misuse-resistant mode based on SCT-2.
*/

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "lilliput-ae-ii.h"
#include "cipher.h"


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
    _encrypt_message(key, ciphertext_len, ciphertext, nonce, tag, message);

    RAM_DATA_BYTE auth[BLOCK_BYTES];
    process_associated_data(key, auth_data_len, auth_data, auth);

    RAM_DATA_BYTE effective_tag[TAG_BYTES];
    _generate_tag(key, ciphertext_len, message, nonce, auth, effective_tag);

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
