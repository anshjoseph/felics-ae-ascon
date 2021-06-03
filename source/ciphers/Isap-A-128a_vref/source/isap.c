#include <stdio.h>
#include <string.h>
#include "api.h"
#include "isap.h"
#include "Ascon-reference.h"

const uint8_t ISAP_IV_A[] = {0x01,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};
const uint8_t ISAP_IV_KA[] = {0x02,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};
const uint8_t ISAP_IV_KE[] = {0x03,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};

/******************************************************************************/
/*                                   IsapRk                                   */
/******************************************************************************/

void isap_rk(
	const uint8_t *k,
	const uint8_t *iv,
	const uint8_t *in,
	const size_t inlen,
	uint8_t *out,
	const size_t outlen
){
	// Init State
	uint8_t state[ISAP_STATE_SZ];
	Ascon_Initialize(state);
	Ascon_AddBytes(state,k,0,CRYPTO_KEYBYTES);
	Ascon_AddBytes(state,iv,CRYPTO_KEYBYTES,ISAP_IV_SZ);
	Ascon_Permute_Nrounds(state,ISAP_sK);

	// Absorb
	for (size_t i = 0; i < inlen*8-1; i++){
		size_t cur_byte_pos = i/8;
		size_t cur_bit_pos = 7-(i%8);
		uint8_t cur_bit = ((in[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
		Ascon_AddBytes(state,(const uint8_t*)&cur_bit,0,1);
		Ascon_Permute_Nrounds(state,ISAP_sB);
	}
	uint8_t cur_bit = ((in[inlen-1]) & 0x01) << 7;
	Ascon_AddBytes(state,(const uint8_t*)&cur_bit,0,1);
	Ascon_Permute_Nrounds(state,ISAP_sK);

	// Squeeze K*
	Ascon_ExtractBytes(state,out,0,outlen);
}

/******************************************************************************/
/*                                  IsapMac                                   */
/******************************************************************************/

void isap_mac(
	const uint8_t *k,
	const uint8_t *npub,
	const uint8_t *ad, const size_t adlen,
	const uint8_t *c, const size_t clen,
	uint8_t *tag
){
	// Init State
	uint8_t state[ISAP_STATE_SZ];
	Ascon_Initialize(state);
	Ascon_AddBytes(state,npub,0,CRYPTO_NPUBBYTES);
	Ascon_AddBytes(state,ISAP_IV_A,CRYPTO_NPUBBYTES,ISAP_IV_SZ);
	Ascon_Permute_Nrounds(state,ISAP_sH);

	// Absorb AD
	size_t rate_bytes_avail = ISAP_rH_SZ;
	uint8_t cur_ad;
	for (size_t i = 0; i < adlen; i++){
		if(rate_bytes_avail == 0){
			Ascon_Permute_Nrounds(state,ISAP_sH);
			rate_bytes_avail = ISAP_rH_SZ;
		}
		cur_ad = ad[i];
		Ascon_AddBytes(state,&cur_ad,ISAP_rH_SZ-rate_bytes_avail,1);
		rate_bytes_avail--;
	}

	// Absorb Padding: 0x80
	if(rate_bytes_avail == 0){
		Ascon_Permute_Nrounds(state,ISAP_sH);
		rate_bytes_avail = ISAP_rH_SZ;
	}
	uint8_t pad = 0x80;
	Ascon_AddBytes(state,&pad,ISAP_rH_SZ-rate_bytes_avail,1);
	Ascon_Permute_Nrounds(state,ISAP_sH);

	// Domain Seperation: 0x01
	uint8_t dom_sep = 0x01;
	Ascon_AddBytes(state,&dom_sep,ISAP_STATE_SZ-1,1);

	// Absorb C
	rate_bytes_avail = ISAP_rH_SZ;
	uint8_t cur_c;
	for (size_t i = 0; i < clen; i++){
		cur_c = c[i];
		Ascon_AddBytes(state,&cur_c,ISAP_rH_SZ-rate_bytes_avail,1);
		rate_bytes_avail--;
		if(rate_bytes_avail == 0){
			Ascon_Permute_Nrounds(state,ISAP_sH);
			rate_bytes_avail = ISAP_rH_SZ;
		}
	}

	// Absorb Padding: 0x80
	pad = 0x80;
	Ascon_AddBytes(state,&pad,ISAP_rH_SZ-rate_bytes_avail,1);
	Ascon_Permute_Nrounds(state,ISAP_sH);

	// Derive Ka*
	uint8_t y[CRYPTO_KEYBYTES];
	uint8_t ka_star[CRYPTO_KEYBYTES];
	Ascon_ExtractBytes(state,y,0,CRYPTO_KEYBYTES);
	isap_rk(k,ISAP_IV_KA,y,CRYPTO_KEYBYTES,ka_star,CRYPTO_KEYBYTES);

	// Squeezing Tag
	Ascon_OverwriteBytes(state,ka_star,0,CRYPTO_KEYBYTES);
	Ascon_Permute_Nrounds(state,ISAP_sH);
	Ascon_ExtractBytes(state,tag,0,CRYPTO_KEYBYTES);
}

/******************************************************************************/
/*                                  IsapEnc                                   */
/******************************************************************************/

void isap_enc(
	const uint8_t *k,
	const uint8_t *npub,
	const uint8_t *m, const size_t mlen,
	uint8_t *c
){
	// Derive Ke*
	uint8_t state[ISAP_STATE_SZ];
	isap_rk(k,ISAP_IV_KE,npub,CRYPTO_NPUBBYTES,state,ISAP_STATE_SZ-CRYPTO_NPUBBYTES);
	Ascon_OverwriteBytes(state,npub,ISAP_STATE_SZ-CRYPTO_NPUBBYTES,CRYPTO_NPUBBYTES);

	// Squeeze Keystream
	size_t key_bytes_avail = 0;
	for (size_t i = 0; i < mlen; i++) {
		if(key_bytes_avail == 0){
			Ascon_Permute_Nrounds(state,ISAP_sE);
			key_bytes_avail = ISAP_rH_SZ;
		}
		uint8_t keybyte;
		Ascon_ExtractBytes(state,&keybyte,i%ISAP_rH_SZ,1);
		c[i] = m[i] ^ keybyte;
		key_bytes_avail--;
	}
}
