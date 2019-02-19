#include <stdint.h>
#include <string.h>

#include "aes.h"
#include "aes_common.h"
#include "constants.h"


void aes_invshiftcol(uint8_t *data, uint8_t shift)
{
	uint8_t tmp[4];

	
	tmp[0] = data[0];
	tmp[1] = data[4];
	tmp[2] = data[8];
	tmp[3] = data[12];

	data[0] = tmp[(4 - shift + 0) & 3];
	data[4] = tmp[(4 - shift + 1) & 3];
	data[8] = tmp[(4 - shift + 2) & 3];
	data[12] = tmp[(4 - shift + 3) & 3];
}

static void aes_dec_round(uint8_t *block, uint8_t *roundKey)
{
	uint8_t tmp[16];
	uint8_t i;
	uint8_t t, u, v, w;

	
	/* keyAdd */
	for (i = 0; i < 16; ++i)
	{
		tmp[i] = block[i] ^ READ_ROUND_KEY_BYTE(roundKey[i]);
	}
	
	/* mixColums */
	for (i = 0; i < 4; ++i)
	{
		t = tmp[4 * i + 3] ^ tmp[4 * i + 2];
		u = tmp[4 * i + 1] ^ tmp[4 * i + 0];
		v = t ^ u;
		v = gmul_o(0x09, v);
		w = v ^ gmul_o(0x04, tmp[4 * i + 2] ^ tmp[4 * i + 0]);
		v = v ^ gmul_o(0x04, tmp[4 * i + 3] ^ tmp[4 * i + 1]);
		
		block[4 * i + 3] = tmp[4 * i + 3] ^ v ^ gmul_o(0x02, tmp[4 * i + 0] ^ tmp[4 * i + 3]);
		block[4 * i + 2] = tmp[4 * i + 2] ^ w ^ gmul_o(0x02, t);
		block[4 * i + 1] = tmp[4 * i + 1] ^ v ^ gmul_o(0x02, tmp[4 * i + 2] ^ tmp[4 * i + 1]);
		block[4 * i + 0] = tmp[4 * i + 0] ^ w ^ gmul_o(0x02, u);

		
	}
	
	/* shiftRows */
	aes_invshiftcol(block + 1, 1);
	aes_invshiftcol(block + 2, 2);
	aes_invshiftcol(block + 3, 3);
	
	/* subBytes */
	for (i = 0; i < 16; ++i)
	{
		block[i] = READ_SBOX_BYTE(aes_invsbox[block[i]]);
	}
}

static void aes_dec_firstround(uint8_t *block, uint8_t *roundKey)
{
	uint8_t i;

	
	/* keyAdd */
	for (i = 0; i < 16; ++i)
	{
		block[i] ^= READ_ROUND_KEY_BYTE(roundKey[i]);
	}
	
	/* shiftRows */
	aes_invshiftcol(block + 1, 1);
	aes_invshiftcol(block + 2, 2);
	aes_invshiftcol(block + 3, 3);
	
	/* subBytes */
	for (i = 0; i < 16; ++i)
	{
		block[i] = READ_SBOX_BYTE(aes_invsbox[block[i]]);
	}
}

static void _Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i;

	
	aes_dec_firstround(block, roundKeys + 16 * 10);

	for (i = 9; i > 0; --i)
	{
		aes_dec_round(block, roundKeys + 16 * i);
	}
	
	for (i = 0; i < 16; ++i)
	{
		block[i] ^= READ_ROUND_KEY_BYTE(roundKeys[i]);
	}
}

void AES_set_decrypt_key(uint8_t *k, size_t bits, AES_KEY *key)
{
    (void)bits;
    AES_RunKeySchedule(k, key->roundkeys);
}

void AES_decrypt(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE], AES_KEY *k)
{
    memcpy(out, in, BLOCK_SIZE);
    _Decrypt(out, k->roundkeys);
}
