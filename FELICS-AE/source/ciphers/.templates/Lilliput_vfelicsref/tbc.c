#include <stdint.h>
#include <string.h>

#include "cipher.h"

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
    RAM_DATA_BYTE TK[TWEAKEY_BYTES];
    tweakey_state_init(TK, key, tweak);
    tweakey_state_extract(TK, 0, RTK[0]);

    for (uint8_t i=1; i<ROUNDS; i++)
    {
        tweakey_state_update(TK);
        tweakey_state_extract(TK, i, RTK[i]);
    }
}


static uint8_t _Fj(uint8_t Xj, const uint8_t RTKj)
{
    return READ_ROM_DATA_BYTE(S[Xj ^ RTKj]);
}

static void _nonlinear_layer(uint8_t X[BLOCK_BYTES], const uint8_t RTK[ROUND_TWEAKEY_BYTES])
{
    for (size_t j=0; j<8; j++)
    {
        X[15-j] ^= _Fj(X[j], RTK[j]);
    }
}

static void _linear_layer(uint8_t X[BLOCK_BYTES])
{
    for (size_t j=1; j<8; j++)
    {
        X[15] ^= X[j];
    }

    for (size_t j=14; j>8; j--)
    {
        X[j] ^= X[7];
    }
}

static void _permutation_layer(uint8_t X[BLOCK_BYTES], permutation p)
{
    if (p == PERMUTATION_NONE)
    {
        return;
    }

    RAM_DATA_BYTE X_old[BLOCK_BYTES];
    memcpy(X_old, X, BLOCK_BYTES);

    const uint8_t *pi = PERMUTATIONS[p];

    for (size_t j=0; j<BLOCK_BYTES; j++)
    {
        X[READ_ROM_DATA_BYTE(pi[j])] = X_old[j];
    }
}

static void _one_round_egfn(uint8_t X[BLOCK_BYTES], const uint8_t RTK[ROUND_TWEAKEY_BYTES], permutation p)
{
    _nonlinear_layer(X, RTK);
    _linear_layer(X);
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

    RAM_DATA_BYTE TK[TWEAKEY_BYTES];
    RAM_DATA_BYTE RTK[ROUND_TWEAKEY_BYTES];
    tweakey_state_init(TK, key, tweak);

    for (unsigned i=0; i<ROUNDS-1; i++)
    {
        tweakey_state_extract(TK, i, RTK);
        _one_round_egfn(ciphertext, RTK, PERMUTATION_ENCRYPTION);
        tweakey_state_update(TK);
    }

    tweakey_state_extract(TK, ROUNDS-1, RTK);
    _one_round_egfn(ciphertext, RTK, PERMUTATION_NONE);
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

    for (unsigned i=0; i<ROUNDS-1; i++)
    {
        _one_round_egfn(message, RTK[ROUNDS-1-i], PERMUTATION_DECRYPTION);
    }

    _one_round_egfn(message, RTK[0], PERMUTATION_NONE);
}
