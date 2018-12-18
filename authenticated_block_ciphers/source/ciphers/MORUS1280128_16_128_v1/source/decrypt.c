/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>

#include "cipher.h"
#include "constants.h"

#include <string.h>
#include <stdlib.h>



 


int32_t morus_tag_verification(uint64_t msglen, uint64_t adlen, const uint8_t *c, uint64_t state[][4])
{
	int32_t i, j;
	uint8_t t[32];
	int32_t check = 0;

	((uint64_t*)(void*)t)[0] = (adlen << 3);
	((uint64_t*)(void*)t)[1] = (msglen << 3);
	((uint64_t*)(void*)t)[2] = 0;
	((uint64_t*)(void*)t)[3] = 0;

	state[4][0] ^= state[0][0]; state[4][1] ^= state[0][1]; state[4][2] ^= state[0][2]; state[4][3] ^= state[0][3];

	for (i = 0; i < 10; i++) morus_stateupdate((uint64_t*)(void*)t, state);

	for (j = 0; j < 4; j++) {
		state[0][j] ^= state[1][(j + 1) & 3] ^ (state[2][j] & state[3][j]);
	}

	//in this program, the mac length is assumed to be a multiple of bytes
	//verification
	for (i = 0; i < 16; i++) check |= (c[msglen + i] ^ ((uint8_t *)(void*)state[0])[i]);
	if (0 == check) return 0;
	else return -1;

}

// one step of decryption: it decrypts a 32-byte block
void morus_dec_aut_step(uint8_t *plaintextblock,
	const uint8_t *ciphertextblock, uint64_t state[][4])
{

	//decryption
	((uint64_t*)(void*)plaintextblock)[0] = ((uint64_t*)(void*)ciphertextblock)[0] ^ state[0][0] ^ state[1][1] ^ (state[2][0] & state[3][0]);
	((uint64_t*)(void*)plaintextblock)[1] = ((uint64_t*)(void*)ciphertextblock)[1] ^ state[0][1] ^ state[1][2] ^ (state[2][1] & state[3][1]);
	((uint64_t*)(void*)plaintextblock)[2] = ((uint64_t*)(void*)ciphertextblock)[2] ^ state[0][2] ^ state[1][3] ^ (state[2][2] & state[3][2]);
	((uint64_t*)(void*)plaintextblock)[3] = ((uint64_t*)(void*)ciphertextblock)[3] ^ state[0][3] ^ state[1][0] ^ (state[2][3] & state[3][3]);

	morus_stateupdate(((uint64_t*)(void*)plaintextblock), state);
	
}

// decrypt a partial block
void morus_dec_aut_partialblock(uint8_t *plaintext,
	const uint8_t *ciphertext, uint64_t len, uint64_t state[][4])
{
	uint8_t plaintextblock[32], ciphertextblock[32];

	memset(ciphertextblock, 0, 32);
	memcpy(ciphertextblock, ciphertext, len);

	//decryption
	((uint64_t*)(void*)plaintextblock)[0] = ((uint64_t*)(void*)ciphertextblock)[0] ^ state[0][0] ^ state[1][1] ^ (state[2][0] & state[3][0]);
	((uint64_t*)(void*)plaintextblock)[1] = ((uint64_t*)(void*)ciphertextblock)[1] ^ state[0][1] ^ state[1][2] ^ (state[2][1] & state[3][1]);
	((uint64_t*)(void*)plaintextblock)[2] = ((uint64_t*)(void*)ciphertextblock)[2] ^ state[0][2] ^ state[1][3] ^ (state[2][2] & state[3][2]);
	((uint64_t*)(void*)plaintextblock)[3] = ((uint64_t*)(void*)ciphertextblock)[3] ^ state[0][3] ^ state[1][0] ^ (state[2][3] & state[3][3]);

	memcpy(plaintext, plaintextblock, len);
	memset(plaintextblock, 0, 32);
	memcpy(plaintextblock, plaintext, len);

	morus_stateupdate(((uint64_t*)(void*)plaintextblock), state);
}




/* ------------------------------------ */

int32_t crypto_aead_decrypt(
	uint8_t *m, uint64_t *mlen,
	uint8_t *nsec,
	const uint8_t *c, uint64_t clen,
	const uint8_t *ad, uint64_t adlen,
	const uint8_t *npub,
	const uint8_t *k
	)
{
  uint32_t i;
	uint8_t ciphertextblock[32];
	uint64_t  morus_state[5][4];

	if (clen < 16) return -1;
	
	//memcpy(tab0, ad, 16);

	morus_initialization(k, npub, morus_state);

	//process the associated data
	for (i = 0; (i + 32) <= adlen; i += 32)
	{
		morus_enc_aut_step(ad + i, ciphertextblock, morus_state);
	}


	// deal with the partial block of associated data
	// in this program, we assume that the message length is a multiple of bytes.
	if ((adlen & 0x1f) != 0)
	{
		morus_enc_aut_partialblock(ad + i, ciphertextblock, adlen & 0x1f, morus_state);
	}
	
	
	
	// decrypt the ciphertext
	*mlen = clen - 16;
	for (i = 0; (i + 32) <= *mlen; i += 32)
	{
		morus_dec_aut_step(m + i, c + i, morus_state);
	}

	// Deal with the partial block
	// In this program, we assume that the message length is a multiple of bytes.
	if ((*mlen & 0x1f) != 0) {
		morus_dec_aut_partialblock(m + i, c + i, *mlen & 0x1f, morus_state);
	}

	uint32_t adlenb = (uint32_t)(adlen);
	// we assume that the tag length is a multiple of bytes
// verification
	//memcpy(m, tab0, 16);

	return morus_tag_verification(*mlen, (uint64_t)adlenb, c, morus_state);
}



uint8_t Decrypt(uint8_t *block, int32_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, int32_t  adlen, uint8_t *c, uint8_t *roundKeys)
{
	/* Add here the cipher decryption implementation */

		static uint8_t *nsec;
	nsec = malloc(CRYPTO_NSECBYTES);
	
	//length of inputs and param
	uint64_t mlenb = (uint64_t) mlen;
	uint64_t clen = mlen + CRYPTO_ABYTES;
	
	uint8_t adb[adlen];
	//adb = (uint8_t *) malloc(adlen * sizeof(uint8_t) );
	memcpy(adb, ad, adlen);
	
	//memcpy(block, adb, 16);
	
	//if(adlen !=16){
	return crypto_aead_decrypt(
	block, &mlenb,
	nsec,
	c, clen,
	adb, (uint64_t) adlen,
	npub,
	key
	);//}
	
	
	//free(adb);
	
}




