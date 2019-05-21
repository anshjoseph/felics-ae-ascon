#include <stdint.h>
#include <string.h>

#include "cipher.h"

#include "constants.h"
#include "parameters.h"
#include "random.h"
#include "tbc.h"
#include "tweakey.h"


static void _state_init(
    uint8_t X[BLOCK_BYTES],
    uint8_t Y[BLOCK_BYTES],
    uint8_t Z[BLOCK_BYTES],
    const uint8_t message[BLOCK_BYTES]
)
{
    RAM_DATA_BYTE SHARES_0[BLOCK_BYTES];
    RAM_DATA_BYTE SHARES_1[BLOCK_BYTES];
    randombytes(sizeof(SHARES_0), SHARES_0);
    randombytes(sizeof(SHARES_1), SHARES_1);

    memcpy(X, SHARES_0, BLOCK_BYTES);
    memcpy(Y, SHARES_1, BLOCK_BYTES);
    for (uint8_t i=0; i<BLOCK_BYTES; i++)
    {
        Z[i] = message[i] ^ SHARES_0[i] ^ SHARES_1[i];
    }
}


static void _compute_round_tweakeys(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    uint8_t RTK_X[ROUNDS][ROUND_TWEAKEY_BYTES],
    uint8_t RTK_Y[ROUNDS][ROUND_TWEAKEY_BYTES]
)
{
    RAM_DATA_BYTE TK_X[TWEAKEY_BYTES];
    RAM_DATA_BYTE TK_Y[TWEAKEY_BYTES];
    tweakey_state_init(TK_X, TK_Y, key, tweak);
    tweakey_state_extract(TK_X, TK_Y, 0, RTK_X[0], RTK_Y[0]);

    for (uint8_t i=1; i<ROUNDS; i++)
    {
        tweakey_state_update(TK_X, TK_Y);
        tweakey_state_extract(TK_X, TK_Y, i, RTK_X[i], RTK_Y[i]);
    }
}


static void _nonlinear_layer(
    uint8_t X[BLOCK_BYTES],
    uint8_t Y[BLOCK_BYTES],
    uint8_t Z[BLOCK_BYTES],
    const uint8_t RTK_X[ROUND_TWEAKEY_BYTES],
    const uint8_t RTK_Y[ROUND_TWEAKEY_BYTES]
)
{
    uint8_t x_hi, y_hi, z_hi;   // High nibbles for the Feistel network
    uint8_t x_lo, y_lo, z_lo;   // Low nibbles for the Feistel network
    uint8_t tmp0, tmp1, tmp2;
    RAM_DATA_BYTE TMP_X[ROUND_TWEAKEY_BYTES];
    RAM_DATA_BYTE TMP_Y[ROUND_TWEAKEY_BYTES];
    RAM_DATA_BYTE TMP_Z[ROUND_TWEAKEY_BYTES];

    // Apply the RTK to two shares
    for (size_t j=0; j<ROUND_TWEAKEY_BYTES; j++)
    {
        TMP_X[j] = X[j] ^ RTK_X[j];
        TMP_Y[j] = Y[j] ^ RTK_Y[j];
    }

    // Threshold Implementation of the 8-bit S-box
    for (size_t j=0; j<ROUND_TWEAKEY_BYTES; j++)
    {
        // Decomposition into nibbles
        x_hi = TMP_X[j] >> 4;
        x_lo = TMP_X[j] & 0xf;
        y_hi = TMP_Y[j] >> 4;
        y_lo = TMP_Y[j] & 0xf;
        z_hi = Z[j] >> 4;
        z_lo = Z[j] & 0xf;
        // First 4-bit S-box
        tmp0 = READ_ROM_DATA_BYTE(G[(y_lo&7)>>1][z_lo]);
        tmp1 = READ_ROM_DATA_BYTE(G[(z_lo&7)>>1][x_lo]);
        tmp2 = READ_ROM_DATA_BYTE(G[(x_lo&7)>>1][y_lo]);
        x_hi ^= READ_ROM_DATA_BYTE(F[tmp1][tmp2]);
        y_hi ^= READ_ROM_DATA_BYTE(F[tmp2][tmp0]);
        z_hi ^= READ_ROM_DATA_BYTE(F[tmp0][tmp1]);
        // Second 4-bit S-box
        tmp0 = READ_ROM_DATA_BYTE(P[READ_ROM_DATA_BYTE(Q[y_hi&3 ^ (y_hi&8)>>1][z_hi])]);
        tmp1 = READ_ROM_DATA_BYTE(P[READ_ROM_DATA_BYTE(Q[z_hi&3 ^ (z_hi&8)>>1][x_hi])]);
        tmp2 = READ_ROM_DATA_BYTE(P[READ_ROM_DATA_BYTE(Q[x_hi&3 ^ (x_hi&8)>>1][y_hi])]);
        x_lo ^= READ_ROM_DATA_BYTE(Q[tmp1&3 ^ (tmp1&8)>>1][tmp2]);
        y_lo ^= READ_ROM_DATA_BYTE(Q[tmp2&3 ^ (tmp2&8)>>1][tmp0]);
        z_lo ^= READ_ROM_DATA_BYTE(Q[tmp0&3 ^ (tmp0&8)>>1][tmp1]);
        // Third 4-bit S-box
        tmp0 = READ_ROM_DATA_BYTE(G[(y_lo&7)>>1][z_lo]) ^ 1;
        tmp1 = READ_ROM_DATA_BYTE(G[(z_lo&7)>>1][x_lo]);
        tmp2 = READ_ROM_DATA_BYTE(G[(x_lo&7)>>1][y_lo]);
        x_hi ^= READ_ROM_DATA_BYTE(F[tmp1][tmp2]);
        y_hi ^= READ_ROM_DATA_BYTE(F[tmp2][tmp0]);
        z_hi ^= READ_ROM_DATA_BYTE(F[tmp0][tmp1]);
        // Build bytes from nibbles
        TMP_X[j] = (x_hi << 4 | x_lo);
        TMP_Y[j] = (y_hi << 4 | y_lo);
        TMP_Z[j] = (z_hi << 4 | z_lo);
    }

    for (size_t j=0; j<8; j++)
    {
        size_t dest_j = 15-j;
        X[dest_j] ^= TMP_X[j];
        Y[dest_j] ^= TMP_Y[j];
        Z[dest_j] ^= TMP_Z[j];
    }
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

    RAM_DATA_BYTE X_old[BLOCK_BYTES];
    memcpy(X_old, X, BLOCK_BYTES);

    const uint8_t *pi = PERMUTATIONS[p];

    for (size_t j=0; j<BLOCK_BYTES; j++)
    {
        X[READ_ROM_DATA_BYTE(pi[j])] = X_old[j];
    }
}

static void _one_round_egfn(
    uint8_t X[BLOCK_BYTES],
    uint8_t Y[BLOCK_BYTES],
    uint8_t Z[BLOCK_BYTES],
    const uint8_t RTK_X[ROUND_TWEAKEY_BYTES],
    const uint8_t RTK_Y[ROUND_TWEAKEY_BYTES],
    permutation p
)
{
    _nonlinear_layer(X, Y, Z, RTK_X, RTK_Y);
    _linear_layer(X);
    _linear_layer(Y);
    _linear_layer(Z);
    _permutation_layer(X, p);
    _permutation_layer(Y, p);
    _permutation_layer(Z, p);
}


void lilliput_tbc_encrypt(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t message[BLOCK_BYTES],
    uint8_t ciphertext[BLOCK_BYTES]
)
{
    RAM_DATA_BYTE X[BLOCK_BYTES];
    RAM_DATA_BYTE Y[BLOCK_BYTES];
    RAM_DATA_BYTE Z[BLOCK_BYTES];
    _state_init(X, Y, Z, message);

    RAM_DATA_BYTE TK_X[TWEAKEY_BYTES];
    RAM_DATA_BYTE TK_Y[TWEAKEY_BYTES];
    RAM_DATA_BYTE RTK_X[ROUND_TWEAKEY_BYTES];
    RAM_DATA_BYTE RTK_Y[ROUND_TWEAKEY_BYTES];
    tweakey_state_init(TK_X, TK_Y, key, tweak);

    for (unsigned i=0; i<ROUNDS-1; i++)
    {
        tweakey_state_extract(TK_X, TK_Y, i, RTK_X, RTK_Y);
        _one_round_egfn(X, Y, Z, RTK_X, RTK_Y, PERMUTATION_ENCRYPTION);
        tweakey_state_update(TK_X, TK_Y);
    }

    tweakey_state_extract(TK_X, TK_Y, ROUNDS-1, RTK_X, RTK_Y);
    _one_round_egfn(X, Y, Z, RTK_X, RTK_Y, PERMUTATION_NONE);

    for (unsigned i=0; i<BLOCK_BYTES; i++)
    {
        ciphertext[i] = X[i] ^ Y[i] ^ Z[i];
    }
}

void lilliput_tbc_decrypt(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t ciphertext[BLOCK_BYTES],
    uint8_t message[BLOCK_BYTES]
)
{
    RAM_DATA_BYTE X[BLOCK_BYTES];
    RAM_DATA_BYTE Y[BLOCK_BYTES];
    RAM_DATA_BYTE Z[BLOCK_BYTES];
    _state_init(X, Y, Z, ciphertext);

    RAM_DATA_BYTE RTK_X[ROUNDS][ROUND_TWEAKEY_BYTES];
    RAM_DATA_BYTE RTK_Y[ROUNDS][ROUND_TWEAKEY_BYTES];
    _compute_round_tweakeys(key, tweak, RTK_X, RTK_Y);

    for (unsigned i=0; i<ROUNDS-1; i++)
    {
        _one_round_egfn(X, Y, Z, RTK_X[ROUNDS-1-i], RTK_Y[ROUNDS-1-i], PERMUTATION_DECRYPTION);
    }

    _one_round_egfn(X, Y, Z, RTK_X[0], RTK_Y[0], PERMUTATION_NONE);

    for (size_t i=0; i<BLOCK_BYTES; i++)
    {
        message[i] = X[i] ^ Y[i] ^ Z[i];
    }
}
