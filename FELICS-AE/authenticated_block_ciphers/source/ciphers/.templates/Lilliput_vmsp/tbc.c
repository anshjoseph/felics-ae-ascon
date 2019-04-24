#include <stdint.h>
#include <string.h>

#include <stdio.h>

#include "constants.h"
#include "parameters.h"
#include "tbc.h"
#include "tweakey.h"


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
    uint8_t TK[TWEAKEY_BYTES];
    tweakey_state_init(TK, key, tweak);
    tweakey_state_extract(TK, 0, RTK[0]);

    for (uint8_t i=1; i<ROUNDS; i++)
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

    uint8_t RTK[ROUNDS][ROUND_TWEAKEY_BYTES];
    _compute_round_tweakeys(key, tweak, RTK);

    for (unsigned i=0; i<ROUNDS-1; i++)
    {
        nonlinear_and_linear(ciphertext, RTK[i]);
        permutation_enc(ciphertext);
    }

    nonlinear_and_linear(ciphertext, RTK[ROUNDS-1]);
}

void lilliput_tbc_decrypt(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t ciphertext[BLOCK_BYTES],
    uint8_t message[BLOCK_BYTES]
)
{
    _state_init(message, ciphertext);

    uint8_t RTK[ROUNDS][ROUND_TWEAKEY_BYTES];
    _compute_round_tweakeys(key, tweak, RTK);

    for (unsigned i=0; i<ROUNDS-1; i++)
    {
        nonlinear_and_linear(message, RTK[ROUNDS-1-i]);
        permutation_dec(message);
    }

    nonlinear_and_linear(message, RTK[0]);
}
