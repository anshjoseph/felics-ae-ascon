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


void nonlinear(uint8_t X[BLOCK_BYTES], const uint8_t RTK[ROUND_TWEAKEY_BYTES]);
void permutation_enc(uint8_t X[BLOCK_BYTES]);
void permutation_dec(uint8_t X[BLOCK_BYTES]);

static void _permutation_layer(uint8_t X[BLOCK_BYTES], permutation p)
{
    switch (p)
    {
        case PERMUTATION_NONE:
            return;
        case PERMUTATION_ENCRYPTION:
            permutation_enc(X);
            break;
        case PERMUTATION_DECRYPTION:
            permutation_dec(X);
            break;
    }
}

static void _one_round_egfn(uint8_t X[BLOCK_BYTES], const uint8_t RTK[ROUND_TWEAKEY_BYTES], permutation p)
{
    nonlinear(X, RTK);
    linear(X);
    _permutation_layer(X, p);
}


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

    for (uint8_t i=0; i<ROUNDS-1; i++)
    {
        _one_round_egfn(ciphertext, RTK[i], PERMUTATION_ENCRYPTION);
    }

    _one_round_egfn(ciphertext, RTK[ROUNDS-1], PERMUTATION_NONE);
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

    for (uint8_t i=0; i<ROUNDS-1; i++)
    {
        _one_round_egfn(message, RTK[ROUNDS-1-i], PERMUTATION_DECRYPTION);
    }

    _one_round_egfn(message, RTK[0], PERMUTATION_NONE);
}
