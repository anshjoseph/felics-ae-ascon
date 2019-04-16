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


static void _nonlinear_layer(uint8_t X[BLOCK_BYTES], const uint8_t RTK[ROUND_TWEAKEY_BYTES])
{
    /* uint8_t F[ROUND_TWEAKEY_BYTES]; */

    /* for (size_t j=0; j<ROUND_TWEAKEY_BYTES; j++) */
    /* { */
        __asm__ volatile (
            "clr r4" "\n\t"
            "mov.b %[RTK], r5" "\n\t"
            "mov.b %[X], r6" "\n\t"

            "loopstart%=:" "\n\t"

            /* grab RTK[j] */
            "mov.b @r5, r7" "\n\t"

            /* grab X[j] */
            "mov.b @r6, r8" "\n\t"

            "xor.b r7, r8" "\n\t"
            "mov.b S(r8), r9" "\n\t"

            /* 15-j */
            "mov.b #15, r10" "\n\t" /* TODO reuse r7? */
            "sub.b r4, r10" "\n\t"

            /* Grab X[15-j] */
            "mov.b %[X], r11" "\n\t"
            "add.b r11, r10" "\n\t"
            "mov.b @r10, r11" "\n\t"

            "xor.b r11, r9" "\n\t"

            /* Write back */
            "mov.b r9, @r10" "\n\t"

            /* Loops are hard */
            "inc r4" "\n\t"
            "inc r5" "\n\t"
            "inc r6" "\n\t"

            "cmp #8, r4" "\n\t"
            "jnz loopstart%=" "\n\t"
            :
            : [X] "m" (X), [RTK] "m" (RTK)
        );
    /* } */

    /* for (size_t j=0; j<8; j++) */
    /* { */
    /*     size_t dest_j = 15-j; */
    /*     /\* X[dest_j] ^= F[j]; *\/ */
    /*     X[dest_j] = X[dest_j] ^ F[j]; */
    /* } */
}

static void _linear_layer(uint8_t X[BLOCK_BYTES])
{
    X[15] ^= X[1];
    X[15] ^= X[2];
    X[15] ^= X[3];
    X[15] ^= X[4];
    X[15] ^= X[5];
    X[15] ^= X[6];
    X[15] ^= X[7];

    X[14] ^= X[7];
    X[13] ^= X[7];
    X[12] ^= X[7];
    X[11] ^= X[7];
    X[10] ^= X[7];
    X[9]  ^= X[7];
}

static void _permutation_layer(uint8_t X[BLOCK_BYTES], permutation p)
{
    if (p == PERMUTATION_NONE)
    {
        return;
    }

    uint8_t X_old[BLOCK_BYTES];
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
