#include <stdint.h>
#include <string.h>

#include "aes.h"
#include "aes_common.h"
#include "constants.h"


static void aes_shiftcol(uint8_t *data, uint8_t shift)
{
    uint8_t tmp[4];


    tmp[0] = data[0];
    tmp[1] = data[4];
    tmp[2] = data[8];
    tmp[3] = data[12];

    data[0] = tmp[(shift + 0) & 3];
    data[4] = tmp[(shift + 1) & 3];
    data[8] = tmp[(shift + 2) & 3];
    data[12] = tmp[(shift + 3) & 3];
}

static void aes_enc_round(uint8_t *block, uint8_t *roundKey)
{
    uint8_t tmp[16], t;
    uint8_t i;


    /* subBytes */
    for (i = 0; i < 16; ++i)
    {
        tmp[i] = READ_SBOX_BYTE(sbox[block[i]]);
    }

    /* shiftRows */
    aes_shiftcol(tmp + 1, 1);
    aes_shiftcol(tmp + 2, 2);
    aes_shiftcol(tmp + 3, 3);

    /* mixColums */
    for (i = 0; i < 4; ++i)
    {
        t = tmp[4 * i + 0] ^ tmp[4 * i + 1] ^ tmp[4 * i + 2] ^ tmp[4 * i + 3];

        block[4 * i + 0] =
            GF256MUL_2(tmp[4 * i + 0] ^ tmp[4 * i + 1])
            ^ tmp[4 * i + 0]
            ^ t;

        block[4 * i + 1] =
            GF256MUL_2(tmp[4 * i + 1] ^ tmp[4 * i + 2])
            ^ tmp[4 * i + 1]
            ^ t;

        block[4 * i + 2] =
            GF256MUL_2(tmp[4 * i + 2] ^ tmp[4 * i + 3])
            ^ tmp[4 * i + 2]
            ^ t;

        block[4 * i + 3] =
            GF256MUL_2(tmp[4 * i + 3] ^ tmp[4 * i + 0])
            ^ tmp[4 * i + 3]
            ^ t;
    }

    /* addKey */
    for (i = 0; i < 16; ++i)
    {
        block[i] ^= READ_ROUND_KEY_BYTE(roundKey[i]);
    }
}

static void aes_enc_lastround(uint8_t *block, uint8_t *roundKey)
{
    uint8_t i;


    /* subBytes */
    for (i = 0; i < 16; ++i)
    {
        block[i] = READ_SBOX_BYTE(sbox[block[i]]);
    }

    /* shiftRows */
    aes_shiftcol(block + 1, 1);
    aes_shiftcol(block + 2, 2);
    aes_shiftcol(block + 3, 3);

    /* keyAdd */
    for (i = 0; i < 16; ++i)
    {
        block[i] ^= READ_ROUND_KEY_BYTE(roundKey[i]);
    }
}


static void _Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    uint8_t i;


    for (i = 0; i < 16; ++i)
    {
        block[i] ^= READ_ROUND_KEY_BYTE(roundKeys[i]);
    }

    for (i = 1; i < 10; ++i)
    {
        aes_enc_round(block, roundKeys + 16 * i);
    }

    aes_enc_lastround(block, roundKeys + 16 * 10);
}

void AES_set_encrypt_key(uint8_t *k, size_t bits, AES_KEY *key)
{
    (void)bits;
    AES_RunKeySchedule(k, key->roundkeys);
}

void AES_encrypt(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE], AES_KEY *k)
{
    memcpy(out, in, BLOCK_SIZE);
    _Encrypt(out, k->roundkeys);
}
