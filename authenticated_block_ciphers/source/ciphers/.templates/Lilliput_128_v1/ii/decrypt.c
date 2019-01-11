#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "lilliput-ae-ii.h"
#include "tbc.h"


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

    uint8_t auth[BLOCK_BYTES];
    process_associated_data(key, auth_data_len, auth_data, auth);

    uint8_t effective_tag[TAG_BYTES];
    _generate_tag(key, ciphertext_len, message, nonce, auth, effective_tag);

    return memcmp(tag, effective_tag, TAG_BYTES) == 0;
}

uint8_t Decrypt(uint8_t *block, int32_t mlen, uint8_t *key, uint8_t *npub,
                uint8_t *ad, int32_t adlen, uint8_t *c, uint8_t *roundKeys)
{
    return _lilliput_ae_decrypt(mlen, c, adlen, ad, key, npub, c+mlen, block)
        ? 0 : -1;
}
