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



#ifdef AVR

#define n1 13
#define n2 46
#define n3 38
#define n4 7
#define n5 4

#define rotl(x,n)      (((x) << (n)) | ((x) >> (64-n)))


void morus_stateupdate(const uint64_t* msgblk, uint64_t state[][4])   // call it as fun(state)
{
	uint64_t temp, temp1;

	state[0][0] ^= state[3][0]; state[0][1] ^= state[3][1]; state[0][2] ^= state[3][2]; state[0][3] ^= state[3][3];
	temp = state[3][3];    state[3][3] = state[3][2];  state[3][2] = state[3][1];  state[3][1] = state[3][0];  state[3][0] = temp;
	state[0][0] ^= state[1][0] & state[2][0]; state[0][1] ^= state[1][1] & state[2][1]; state[0][2] ^= state[1][2] & state[2][2]; state[0][3] ^= state[1][3] & state[2][3];
	state[0][0] = rotl(state[0][0], n1);  state[0][1] = rotl(state[0][1], n1);       state[0][2] = rotl(state[0][2], n1);       state[0][3] = rotl(state[0][3], n1);

	state[1][0] ^= msgblk[0];   state[1][1] ^= msgblk[1];   state[1][2] ^= msgblk[2];   state[1][3] ^= msgblk[3];
	state[1][0] ^= state[4][0]; state[1][1] ^= state[4][1]; state[1][2] ^= state[4][2]; state[1][3] ^= state[4][3];
	temp = state[4][3];    state[4][3] = state[4][1];  state[4][1] = temp;
	temp1 = state[4][2];    state[4][2] = state[4][0];  state[4][0] = temp1;
	state[1][0] ^= (state[2][0] & state[3][0]); state[1][1] ^= (state[2][1] & state[3][1]); state[1][2] ^= (state[2][2] & state[3][2]); state[1][3] ^= (state[2][3] & state[3][3]);
	state[1][0] = rotl(state[1][0], n2);  state[1][1] = rotl(state[1][1], n2);       state[1][2] = rotl(state[1][2], n2);       state[1][3] = rotl(state[1][3], n2);

	state[2][0] ^= msgblk[0];   state[2][1] ^= msgblk[1];   state[2][2] ^= msgblk[2];   state[2][3] ^= msgblk[3];
	state[2][0] ^= state[0][0]; state[2][1] ^= state[0][1]; state[2][2] ^= state[0][2]; state[2][3] ^= state[0][3];
	temp = state[0][0];    state[0][0] = state[0][1];  state[0][1] = state[0][2];  state[0][2] = state[0][3];  state[0][3] = temp;
	state[2][0] ^= state[3][0] & state[4][0]; state[2][1] ^= state[3][1] & state[4][1]; state[2][2] ^= state[3][2] & state[4][2]; state[2][3] ^= state[3][3] & state[4][3];
	state[2][0] = rotl(state[2][0], n3);  state[2][1] = rotl(state[2][1], n3);       state[2][2] = rotl(state[2][2], n3);       state[2][3] = rotl(state[2][3], n3);

	state[3][0] ^= msgblk[0];   state[3][1] ^= msgblk[1];   state[3][2] ^= msgblk[2];   state[3][3] ^= msgblk[3];
	state[3][0] ^= state[1][0]; state[3][1] ^= state[1][1]; state[3][2] ^= state[1][2]; state[3][3] ^= state[1][3];
	temp = state[1][3];    state[1][3] = state[1][1];  state[1][1] = temp;
	temp1 = state[1][2];    state[1][2] = state[1][0];  state[1][0] = temp1;
	state[3][0] ^= state[4][0] & state[0][0]; state[3][1] ^= state[4][1] & state[0][1]; state[3][2] ^= state[4][2] & state[0][2]; state[3][3] ^= state[4][3] & state[0][3];
	state[3][0] = rotl(state[3][0], n4);  state[3][1] = rotl(state[3][1], n4);       state[3][2] = rotl(state[3][2], n4);       state[3][3] = rotl(state[3][3], n4);

	state[4][0] ^= msgblk[0];   state[4][1] ^= msgblk[1];   state[4][2] ^= msgblk[2];   state[4][3] ^= msgblk[3];
	state[4][0] ^= state[2][0]; state[4][1] ^= state[2][1]; state[4][2] ^= state[2][2]; state[4][3] ^= state[2][3];
	
	temp = state[2][3];    state[2][3] = state[2][2];  state[2][2] = state[2][1];  state[2][1] = state[2][0];  state[2][0] = temp;
	state[4][0] ^= state[0][0] & state[1][0]; state[4][1] ^= state[0][1] & state[1][1]; state[4][2] ^= state[0][2] & state[1][2]; state[4][3] ^= state[0][3] & state[1][3];
	state[4][0] = rotl(state[4][0], n5);  state[4][1] = rotl(state[4][1], n5);       state[4][2] = rotl(state[4][2], n5);       state[4][3] = rotl(state[4][3], n5);
}

/*The input to the initialization is the 128/256-bit key; 128-bit IV;*/
void morus_initialization(const uint8_t *key, const uint8_t *iv, uint64_t state[][4])
{
	int32_t i;
	uint64_t temp[4] = { 0,0,0,0 };
	uint8_t con[32] = { 0x0,0x1,0x01,0x02,0x03,0x05,0x08,0x0d,0x15,0x22,0x37,0x59,0x90,0xe9,0x79,0x62, 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd };
	uint64_t ekey[4];

	memcpy(ekey, key, 16);
	ekey[3] = ekey[1]; ekey[2] = ekey[0];
	memcpy(state[0], iv, 16);   memset(state[0] + 2, 0, 16);
	memcpy(state[1], ekey, 32);
	memset(state[2], 0xff, 32);
	memset(state[3], 0, 32);
	memcpy(state[4], con, 32);

	for (i = 0; i < 4; i++) temp[i] = 0;
	for (i = 0; i < 16; i++) morus_stateupdate(temp, state);
	for (i = 0; i < 4; i++) state[1][i] ^= ((uint64_t*)(void*)ekey)[i];
}


//the finalization state of MORUS
void morus_tag_generation(uint64_t msglen, uint64_t adlen, uint8_t *c, uint64_t state[][4])
{
	int32_t i, j;
	uint8_t t[32];

	((uint64_t*)(void*)t)[0] = (adlen << 3); ((uint64_t*)(void*)t)[1] = (msglen << 3);
	((uint64_t*)(void*)t)[2] = 0; ((uint64_t*)(void*)t)[3] = 0;

	state[4][0] ^= state[0][0]; state[4][1] ^= state[0][1]; state[4][2] ^= state[0][2]; state[4][3] ^= state[0][3];

	for (i = 0; i < 10; i++) morus_stateupdate((uint64_t*)(void*)t, state);

	for (j = 0; j < 4; j++) {
		state[0][j] ^= state[1][(j + 1) & 3] ^ (state[2][j] & state[3][j]);
	}

	//in this program, the mac length is assumed to be a multiple of bytes
	memcpy(c + msglen, state[0], 16);
}

// one step of encryption: it encrypts a 32-byte block
void morus_enc_aut_step(const uint8_t *plaintextblock, uint8_t *ciphertextblock, uint64_t state[5][4])
{

	//encryption
	((uint64_t*)(void*)ciphertextblock)[0] = ((uint64_t*)(void*)plaintextblock)[0] ^ state[0][0] ^ state[1][1] ^ (state[2][0] & state[3][0]);
	((uint64_t*)(void*)ciphertextblock)[1] = ((uint64_t*)(void*)plaintextblock)[1] ^ state[0][1] ^ state[1][2] ^ (state[2][1] & state[3][1]);
	((uint64_t*)(void*)ciphertextblock)[2] = ((uint64_t*)(void*)plaintextblock)[2] ^ state[0][2] ^ state[1][3] ^ (state[2][2] & state[3][2]);
	((uint64_t*)(void*)ciphertextblock)[3] = ((uint64_t*)(void*)plaintextblock)[3] ^ state[0][3] ^ state[1][0] ^ (state[2][3] & state[3][3]);
	
	morus_stateupdate(((uint64_t*)(void*)plaintextblock), state);

}

// encrypt a partial block
void morus_enc_aut_partialblock(const uint8_t *plaintext,
	uint8_t *ciphertext, uint64_t len, uint64_t state[][4])
{
	uint8_t plaintextblock[32], ciphertextblock[32];

	memset(plaintextblock, 0, 32);
	memcpy(plaintextblock, plaintext, len);

	//encryption
	((uint64_t*)(void*)ciphertextblock)[0] = ((uint64_t*)(void*)plaintextblock)[0] ^ state[0][0] ^ state[1][1] ^ (state[2][0] & state[3][0]);
	((uint64_t*)(void*)ciphertextblock)[1] = ((uint64_t*)(void*)plaintextblock)[1] ^ state[0][1] ^ state[1][2] ^ (state[2][1] & state[3][1]);
	((uint64_t*)(void*)ciphertextblock)[2] = ((uint64_t*)(void*)plaintextblock)[2] ^ state[0][2] ^ state[1][3] ^ (state[2][2] & state[3][2]);
	((uint64_t*)(void*)ciphertextblock)[3] = ((uint64_t*)(void*)plaintextblock)[3] ^ state[0][3] ^ state[1][0] ^ (state[2][3] & state[3][3]);

	memcpy(ciphertext, ciphertextblock, len);

	morus_stateupdate(((uint64_t*)(void*)plaintextblock), state);
}



/*------------------------------*/

int32_t crypto_aead_encrypt(
	uint8_t *c, uint64_t *clen,
	const uint8_t *m, uint64_t mlen,
	const uint8_t *ad, uint64_t adlen,
	const uint8_t *nsec,
	const uint8_t *npub,
	uint8_t *k
	)
{
  uint64_t i;
	uint8_t ciphertextblock[32];
	uint64_t morus_state[5][4];

	//initialization
	morus_initialization(k, npub, morus_state);

	//process the associated data
	for (i = 0; (i + 32) <= adlen; i += 32) {
		morus_enc_aut_step(ad + i, ciphertextblock, morus_state);

	}

	//deal with the partial block of associated data
	//in this program, we assume that the message length is a multiple of bytes.
	if ((adlen & 0x1f) != 0) {
		morus_enc_aut_partialblock(ad + i, ciphertextblock, adlen & 0x1f, morus_state);
	}
	
	//encrypt the plaintext
	for (i = 0; (i + 32) <= mlen; i += 32) {
		morus_enc_aut_step(m + i, c + i, morus_state);
	}

	// Deal with the partial block
	// In this program, we assume that the message length is a multiple of bytes.
	if ((mlen & 0x1f) != 0) {
		morus_enc_aut_partialblock(m + i, c + i, mlen & 0x1f, morus_state);
	}

	//finalization stage, we assume that the tag length is a multiple of bytes
	morus_tag_generation(mlen, adlen, c, morus_state);
	*clen = mlen + 16;
	return 0;
}


/*--------------------------------*/

void Encrypt(uint8_t *block, int32_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, int32_t  adlen, uint8_t *c, uint8_t *roundKeys)
{

	static uint8_t *nsec;
	nsec = malloc(CRYPTO_NSECBYTES);
	
	//length of inputs and param
	uint64_t clen = mlen + CRYPTO_ABYTES;
	
	if(adlen !=16){
	crypto_aead_encrypt(
	c, &clen,
	block, (uint64_t) mlen,
	ad, (uint64_t) adlen,
	nsec,
	npub,
	key
	);}
	else if(adlen ==16){
	crypto_aead_encrypt(
	c, &clen,
	block, (uint64_t) mlen,
	ad, (uint64_t) adlen,
	nsec,
	npub,
	key
	);
	}
	
	
}




#else

/* -------------------------- */

uint64_t rotlsup32(uint64_t x, uint32_t dec){
	uint32_t x0 = (uint32_t)(x>>32) ;
	uint32_t x1 = (uint32_t)(x & 0x00000000FFFFFFFF) ;
	
	uint32_t temp = x1 << (dec-32);
	x1 = (x0<<(dec-32)) | (x1>>(64-dec)) ;
	x0 = temp | (x0>>(64-dec));
	
	x = (((uint64_t)(x0)) <<32 ) | ((uint64_t)(x1));
	
	return x;
}



uint64_t rotlinf32(uint64_t x, uint32_t dec){
	uint32_t x0 = (uint32_t)(x>>32) ;
	uint32_t x1 = (uint32_t)(x & 0x00000000FFFFFFFF) ;
	
	uint32_t temp = x0 >> (32-dec);
	x0 = (x0<<dec) | (x1>>(32-dec));
	x1 = (x1<<dec) | temp;
	
	x = (((uint64_t)(x0)) <<32 ) | ((uint64_t)(x1));
	
	return x;
}


void morus_stateupdate(const uint64_t* msgblk, uint64_t state[][4])   // call it as fun(state)
{
	uint64_t temp, temp1;
	
	//memcpy(tab0, state[4], 16);

	state[0][0] ^= state[3][0]; 
	state[0][1] ^= state[3][1]; 
	state[0][2] ^= state[3][2]; 
	state[0][3] ^= state[3][3];
	temp = state[3][3];    
	state[3][3] = state[3][2];  
	state[3][2] = state[3][1];  
	state[3][1] = state[3][0];  
	state[3][0] = temp;
	state[0][0] ^= state[1][0] & state[2][0]; 
	state[0][1] ^= state[1][1] & state[2][1]; 
	state[0][2] ^= state[1][2] & state[2][2]; 
	state[0][3] ^= state[1][3] & state[2][3];
	state[0][0] = rotlinf32(state[0][0],13);  
	state[0][1] = rotlinf32(state[0][1],13);      
	state[0][2] = rotlinf32(state[0][2],13);       
	state[0][3] = rotlinf32(state[0][3],13);
	

	state[1][0] ^= msgblk[0];   
	state[1][1] ^= msgblk[1];   
	state[1][2] ^= msgblk[2];   
	state[1][3] ^= msgblk[3];
	state[1][0] ^= state[4][0];
	state[1][1] ^= state[4][1]; 
	state[1][2] ^= state[4][2]; 
	state[1][3] ^= state[4][3];
	temp = state[4][3];    
	state[4][3] = state[4][1];  
	state[4][1] = temp;
	temp1 = state[4][2];    
	state[4][2] = state[4][0];  
	state[4][0] = temp1;
	state[1][0] ^= (state[2][0] & state[3][0]); 
	state[1][1] ^= (state[2][1] & state[3][1]); 
	state[1][2] ^= (state[2][2] & state[3][2]); 
	state[1][3] ^= (state[2][3] & state[3][3]);
	state[1][0] = rotlsup32(state[1][0],46);  
	state[1][1] = rotlsup32(state[1][1],46);       
	state[1][2] = rotlsup32(state[1][2],46);       
	state[1][3] = rotlsup32(state[1][3],46);
	

	state[2][0] ^= msgblk[0];   
	state[2][1] ^= msgblk[1];   
	state[2][2] ^= msgblk[2];   
	state[2][3] ^= msgblk[3];
	state[2][0] ^= state[0][0]; 
	state[2][1] ^= state[0][1]; 
	state[2][2] ^= state[0][2]; 
	state[2][3] ^= state[0][3];
	temp = state[0][0];    
	state[0][0] = state[0][1];  
	state[0][1] = state[0][2];  
	state[0][2] = state[0][3];  
	state[0][3] = temp;
	state[2][0] ^= state[3][0] & state[4][0]; 
	state[2][1] ^= state[3][1] & state[4][1]; 
	state[2][2] ^= state[3][2] & state[4][2]; 
	state[2][3] ^= state[3][3] & state[4][3];
	state[2][0] = rotlsup32(state[2][0],38);  
	state[2][1] = rotlsup32(state[2][1],38);       
	state[2][2] = rotlsup32(state[2][2],38);       
	state[2][3] = rotlsup32(state[2][3],38);

	state[3][0] ^= msgblk[0];   
	state[3][1] ^= msgblk[1];   
	state[3][2] ^= msgblk[2];   
	state[3][3] ^= msgblk[3];
	state[3][0] ^= state[1][0]; 
	state[3][1] ^= state[1][1]; 
	state[3][2] ^= state[1][2]; 
	state[3][3] ^= state[1][3];
	temp = state[1][3];    
	state[1][3] = state[1][1];  
	state[1][1] = temp;
	temp1 = state[1][2];    
	state[1][2] = state[1][0];  
	state[1][0] = temp1;
	state[3][0] ^= state[4][0] & state[0][0]; 
	state[3][1] ^= state[4][1] & state[0][1]; 
	state[3][2] ^= state[4][2] & state[0][2]; 
	state[3][3] ^= state[4][3] & state[0][3];
	state[3][0] = rotlinf32(state[3][0],7);  
	state[3][1] = rotlinf32(state[3][1],7);       
	state[3][2] = rotlinf32(state[3][2],7);       
	state[3][3] = rotlinf32(state[3][3],7);

	state[4][0] ^= msgblk[0];   
	state[4][1] ^= msgblk[1];  
	state[4][2] ^= msgblk[2];   
	state[4][3] ^= msgblk[3];
	state[4][0] ^= state[2][0]; 
	state[4][1] ^= state[2][1]; 
	state[4][2] ^= state[2][2]; 
	state[4][3] ^= state[2][3];
	
	temp = state[2][3];    
	state[2][3] = state[2][2];  
	state[2][2] = state[2][1];  
	state[2][1] = state[2][0];  
	state[2][0] = temp;
	state[4][0] ^= state[0][0] & state[1][0]; 
	state[4][1] ^= state[0][1] & state[1][1]; 
	state[4][2] ^= state[0][2] & state[1][2]; 
	state[4][3] ^= state[0][3] & state[1][3];
	state[4][0] = rotlinf32(state[4][0],4);  
	state[4][1] = rotlinf32(state[4][1],4);       
	state[4][2] = rotlinf32(state[4][2],4);       
	state[4][3] = rotlinf32(state[4][3],4);
}



/*The input to the initialization is the 128/256-bit key; 128-bit IV;*/
void morus_initialization(const uint8_t *key, const uint8_t *iv, uint64_t state[][4])
{
	int32_t i;
	uint64_t temp[4] = { 0,0,0,0 };
	uint8_t con[32] = { 0x0,0x1,0x01,0x02,0x03,0x05,0x08,0x0d,0x15,0x22,0x37,0x59,0x90,0xe9,0x79,0x62, 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd };
	uint64_t ekey[4];

	memcpy(ekey, key, 16);
	ekey[3] = ekey[1]; ekey[2] = ekey[0];
	memcpy(state[0], iv, 16);   memset(state[0] + 2, 0, 16);
	memcpy(state[1], ekey, 32);
	memset(state[2], 0xff, 32);
	memset(state[3], 0, 32);
	memcpy(state[4], con, 32);

	for (i = 0; i < 4; i++) temp[i] = 0;
	for (i = 0; i < 16; i++) morus_stateupdate(temp, state);
	for (i = 0; i < 4; i++) state[1][i] ^= ((uint64_t*)(void*)ekey)[i];
}


//the finalization state of MORUS
void morus_tag_generation(uint64_t msglen, uint64_t adlen, uint8_t *c, uint64_t state[][4])
{
	int32_t i, j;
	uint8_t t[32];
	for(i =0; i<32; i++) t[i] = 0;
	
	

	((uint64_t*)(void*)t)[0] = (adlen << 3); 
	((uint64_t*)(void*)t)[1] = (msglen << 3);
	((uint64_t*)(void*)t)[2] = 0; 
	((uint64_t*)(void*)t)[3] = 0;

	state[4][0] ^= state[0][0]; 
	state[4][1] ^= state[0][1]; 
	state[4][2] ^= state[0][2]; 
	state[4][3] ^= state[0][3];
	
	/*uint32_t state32[5][8];
	for(i=0; i<5; i++){
		for(j=0; j<4; j++){
			state32[i][2*j] = (uint32_t)(state[i][j] >> 32) ; 
			state32[i][2*j+1] = (uint32_t)(state[i][j] & 0x00000000FFFFFFFF) ; 
		}
	}*/
	

	//for (i = 0; i < 1; i++) morus_stateupdate32(((uint32_t*)t), state32);
	
	for (i = 0; i < 10; i++) morus_stateupdate(((uint64_t*)(void*)t), state);
	
	/*for(i=0; i<5; i++){
		for(j=0; j<4; j++){
			state[i][j] = (((uint64_t)(state32[i][2*j])) << 32) | ((uint64_t)(state32[i][2*j+1]))  ; 
		}
	}*/
	
	//memcpy(tab0, state[0], 16);
	//tab0[0]=adlen;

	for (j = 0; j < 4; j++) {
		state[0][j] ^= state[1][(j + 1) & 3] ^ (state[2][j] & state[3][j]);
	}
	
	
	//in this program, the mac length is assumed to be a multiple of bytes
	memcpy(c, state[0], 16);
}

// one step of encryption: it encrypts a 32-byte block
void morus_enc_aut_step(const uint8_t *plaintextblock, uint8_t *ciphertextblock, uint64_t state[5][4])
{

	//encryption
	((uint64_t*)(void*)ciphertextblock)[0] = ((uint64_t*)(void*)plaintextblock)[0] ^ state[0][0] ^ state[1][1] ^ (state[2][0] & state[3][0]);
	((uint64_t*)(void*)ciphertextblock)[1] = ((uint64_t*)(void*)plaintextblock)[1] ^ state[0][1] ^ state[1][2] ^ (state[2][1] & state[3][1]);
	((uint64_t*)(void*)ciphertextblock)[2] = ((uint64_t*)(void*)plaintextblock)[2] ^ state[0][2] ^ state[1][3] ^ (state[2][2] & state[3][2]);
	((uint64_t*)(void*)ciphertextblock)[3] = ((uint64_t*)(void*)plaintextblock)[3] ^ state[0][3] ^ state[1][0] ^ (state[2][3] & state[3][3]);
	
	morus_stateupdate(((uint64_t*)(void*)plaintextblock), state);

}

// encrypt a partial block
void morus_enc_aut_partialblock(const uint8_t *plaintext,
	uint8_t *ciphertext, uint64_t len, uint64_t state[][4])
{
	uint8_t plaintextblock[32], ciphertextblock[32];

	memset(plaintextblock, 0, 32);
	memcpy(plaintextblock, plaintext, len);

	//encryption
	((uint64_t*)(void*)ciphertextblock)[0] = ((uint64_t*)(void*)plaintextblock)[0] ^ state[0][0] ^ state[1][1] ^ (state[2][0] & state[3][0]);
	((uint64_t*)(void*)ciphertextblock)[1] = ((uint64_t*)(void*)plaintextblock)[1] ^ state[0][1] ^ state[1][2] ^ (state[2][1] & state[3][1]);
	((uint64_t*)(void*)ciphertextblock)[2] = ((uint64_t*)(void*)plaintextblock)[2] ^ state[0][2] ^ state[1][3] ^ (state[2][2] & state[3][2]);
	((uint64_t*)(void*)ciphertextblock)[3] = ((uint64_t*)(void*)plaintextblock)[3] ^ state[0][3] ^ state[1][0] ^ (state[2][3] & state[3][3]);

	memcpy(ciphertext, ciphertextblock, len);

	morus_stateupdate(((uint64_t*)(void*)plaintextblock), state);
}



/*------------------------------*/

int32_t crypto_aead_encrypt(
	uint8_t *c, uint64_t *clen,
	const uint8_t *m, uint64_t mlen,
	const uint8_t *ad, uint64_t adlen,
	const uint8_t *nsec,
	const uint8_t *npub,
	uint8_t *k
	)
{
  	uint64_t i;
	uint8_t ciphertextblock[32];
	uint64_t morus_state[5][4];

	//initialization
	morus_initialization(k, npub, morus_state);

	//process the associated data
	for (i = 0; (i + 32) <= adlen; i += 32) {
		morus_enc_aut_step(ad + i, ciphertextblock, morus_state);

	}
	

	//deal with the partial block of associated data
	//in this program, we assume that the message length is a multiple of bytes.
	if ((adlen & 0x1f) != 0) {
		morus_enc_aut_partialblock(ad + i, ciphertextblock, adlen & 0x1f, morus_state);
	}
	
	//encrypt the plaintext
	for (i = 0; (i + 32) <= mlen; i += 32) {
		morus_enc_aut_step(m + i, c + i, morus_state);
	}

	// Deal with the partial block
	// In this program, we assume that the message length is a multiple of bytes.
	if ((mlen & 0x1f) != 0) {
		morus_enc_aut_partialblock(m + i, c + i, mlen & 0x1f, morus_state);
	}
	
	uint32_t adlenb = (uint32_t)(adlen);
	//finalization stage, we assume that the tag length is a multiple of bytes
	morus_tag_generation(mlen, (uint64_t)(adlenb), c + mlen, morus_state);
	*clen = mlen + 16;
	
	
	return 0;
}


/*--------------------------------*/

void Encrypt(uint8_t *block, int32_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, int32_t  adlen, uint8_t *c, uint8_t *roundKeys)
{

	static uint8_t *nsec;
	nsec = malloc(CRYPTO_NSECBYTES);
	
	//length of inputs and param
	uint64_t clen = mlen + CRYPTO_ABYTES;
	
	uint8_t *adb;
	adb = (uint8_t *) malloc(adlen * sizeof(uint8_t) );
	memcpy(adb, ad, adlen);
	
	//if(adlen !=16){
	crypto_aead_encrypt(
	c, &clen,
	block, (uint64_t) mlen,
	adb, (uint64_t) adlen,
	nsec,
	npub,
	key
	);//}
	
	
	free(adb);
	
}

#endif


