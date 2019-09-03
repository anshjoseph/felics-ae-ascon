#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "lilliput-ae-ii.h"
#include "cipher.h"


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

    _generate_tag(key, message_len, message, nonce, auth, tag);

    _encrypt_message(key, message_len, message, nonce, tag, ciphertext);
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
