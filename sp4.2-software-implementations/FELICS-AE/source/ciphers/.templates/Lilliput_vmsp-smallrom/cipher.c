#include <stdint.h>
#include <string.h>

#include <stdio.h>

#include "felics/cipher.h"

#include "cipher.h"
#include "constants.h"
#include "tweakey.h"


#define SBOX_BYTE ROM_DATA_BYTE
extern SBOX_BYTE S[256];


static void _state_init(uint8_t X[BLOCK_BYTES], const uint8_t message[BLOCK_BYTES])
{
    memcpy(X, message, BLOCK_BYTES);
}


static void _compute_round_tweakeys(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    uint8_t RTK[ROUNDS][ROUND_TWEAKEY_BYTES]
)
{
    RAM_DATA_BYTE TK[TWEAKEY_BYTES];
    tweakey_state_init(TK, key, tweak);
    tweakey_state_extract(TK, 0, RTK[0]);

    for (size_t i=1; i<ROUNDS; i++)
    {
        tweakey_state_update(TK);
        tweakey_state_extract(TK, i, RTK[i]);
    }
}


/* Assembly routines. */
void nonlinear_and_linear(uint8_t X[BLOCK_BYTES], const uint8_t RTK[ROUND_TWEAKEY_BYTES]);
void permutation_enc(uint8_t X[BLOCK_BYTES]);
void permutation_dec(uint8_t X[BLOCK_BYTES]);


void lilliput_tbc_encrypt(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t message[BLOCK_BYTES],
    uint8_t ciphertext[BLOCK_BYTES]
)
{
    _state_init(ciphertext, message);

    RAM_DATA_BYTE TK[TWEAKEY_BYTES];
    RAM_DATA_BYTE RTK[ROUND_TWEAKEY_BYTES];
    tweakey_state_init(TK, key, tweak);

    for (size_t i=0; i<ROUNDS-1; i++)
    {
        tweakey_state_extract(TK, i, RTK);
        nonlinear_and_linear(ciphertext, RTK);
        permutation_enc(ciphertext);
        tweakey_state_update(TK);
    }

    tweakey_state_extract(TK, ROUNDS-1, RTK);
    nonlinear_and_linear(ciphertext, RTK);
}

void lilliput_tbc_decrypt(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t ciphertext[BLOCK_BYTES],
    uint8_t message[BLOCK_BYTES]
)
{
    _state_init(message, ciphertext);

    RAM_DATA_BYTE RTK[ROUNDS][ROUND_TWEAKEY_BYTES];
    _compute_round_tweakeys(key, tweak, RTK);

    for (size_t i=0; i<ROUNDS-1; i++)
    {
        nonlinear_and_linear(message, RTK[ROUNDS-1-i]);
        permutation_dec(message);
    }

    nonlinear_and_linear(message, RTK[0]);
}
