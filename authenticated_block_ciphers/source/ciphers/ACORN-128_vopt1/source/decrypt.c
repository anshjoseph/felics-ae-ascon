#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"
#include "utils.h"


static void decrypt_32bits_fast(uint64_t *state, uint32_t *plaintextword, uint32_t ciphertextword, uint32_t ca)
{
    unsigned int f, ks;
    uint64_t word_244, word_23, word_160, word_111, word_66, word_196;
    uint64_t word_12,word_235;

    //f  = state[0] ^ (state[107] ^ 1) ^ maj(state[244], state[23], state[160]) ^ ch(state[230], state[111], state[66]) ^ (ca & state[196]) ^ (cb & (*ks));

    word_12  = state[0] >> 12;
    word_235 = state[5] >> 5;
    word_244 = state[5] >> 14;
    word_23  = state[0] >> 23;
    word_160 = state[3] >> 6;
    word_111 = state[2] >> 4;
    word_66  = state[1] >> 5;
    word_196 = state[4] >> 3;

	state[6] ^= (state[5] ^ word_235) & 0xffffffff;
	state[5] ^= (state[4] ^ word_196) & 0xffffffff;
	state[4] ^= (state[3] ^ word_160) & 0xffffffff;
	state[3] ^= (state[2] ^ word_111) & 0xffffffff;
	state[2] ^= (state[1] ^ word_66)  & 0xffffffff;
	state[1] ^= (state[0] ^ word_23)  & 0xffffffff;

	/*
    word_0   = state[0];
    word_107 = state[2];
    word_230 = state[5];
    word_154 = state[3];
    word_61  = state[1];
    word_193 = state[4];
    */

	ks = word_12 ^ state[3] ^ maj(word_235, state[1], state[4]) ^ ch(state[5], word_111, word_66) ;
	f = state[0] ^ (~state[2]) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca); // ^ (cb & *ks);
    *plaintextword = ciphertextword ^ ks;
    f  = f ^ *plaintextword;
	state[6] = state[6] ^ ( (uint64_t)f << 4 );


    state[0] = (state[0] >> 32) | ((state[1] & 0xffffffff) << 29);  //32-(64-61) = 29
    state[1] = (state[1] >> 32) | ((state[2] & 0xffffffff) << 14);  //32-(64-46) = 14
    state[2] = (state[2] >> 32) | ((state[3] & 0xffffffff) << 15);  //32-(64-47) = 15
    state[3] = (state[3] >> 32) | ((state[4] & 0xffffffff) << 7);   //32-(64-39) = 7
    state[4] = (state[4] >> 32) | ((state[5] & 0xffffffff) << 5);   //32-(64-37) = 5
    state[5] = (state[5] >> 32) | ((state[6] & 0xffffffff) << 27);  //32-(64-59) = 27
    state[6] =  state[6] >> 32;

    return;
}


static void decrypt_8bits(uint64_t *state, uint32_t *plaintextword, uint32_t ciphertextword, uint32_t ca, uint32_t cb)
{
    unsigned int f, ks;
    uint64_t word_244, word_23, word_160, word_111, word_66, word_196;
    uint64_t word_12,word_235;

    word_12  = state[0] >> 12;
    word_235 = state[5] >> 5;
    word_244 = state[5] >> 14;
    word_23  = state[0] >> 23;
    word_160 = state[3] >> 6;
    word_111 = state[2] >> 4;
    word_66  = state[1] >> 5;
    word_196 = state[4] >> 3;

	state[6] ^= (state[5] ^ word_235) & 0xff;
	state[5] ^= (state[4] ^ word_196) & 0xff;
	state[4] ^= (state[3] ^ word_160) & 0xff;
	state[3] ^= (state[2] ^ word_111) & 0xff;
	state[2] ^= (state[1] ^ word_66)  & 0xff;
	state[1] ^= (state[0] ^ word_23)  & 0xff;

	ks = word_12 ^ state[3] ^ maj(word_235, state[1], state[4]) ^ ch(state[5], word_111, word_66);
    ks &= 0xff;
	f = state[0] ^ (~state[2]) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca) ^ (cb & ks);
    *plaintextword = ciphertextword ^ ks;
    f  = (f ^ *plaintextword) & 0xff;
	state[6] = state[6] ^ ( (uint64_t)f << 4 );

    state[0] = (state[0] >> 8) | ((state[1] & 0xff) << (29+24));   //32-(64-61) = 29
    state[1] = (state[1] >> 8) | ((state[2] & 0xff) << (14+24));   //32-(64-46) = 14
    state[2] = (state[2] >> 8) | ((state[3] & 0xff) << (15+24));   //32-(64-47) = 15
    state[3] = (state[3] >> 8) | ((state[4] & 0xff) << (7+24));    //32-(64-39) = 7
    state[4] = (state[4] >> 8) | ((state[5] & 0xff) << (5+24));    //32-(64-37) = 5
    state[5] = (state[5] >> 8) | ((state[6] & 0xff) << (27+24));    //32-(64-59) = 27
    state[6] =  state[6] >> 8;

    return;
}


//decrypt a message
static int crypto_aead_decrypt(
	uint8_t *m,size_t *mlen,
	const uint8_t *c,size_t clen,
	const uint8_t *ad,size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
	)
{
    size_t i;
    uint8_t tag[16],check=0;
    uint32_t plaintextword, ciphertextword;

    uint64_t state[7];
    uint32_t ca, cb;

    //initialization stage
    acorn128_initialization_32bitversion(k, npub, state);

    //process the associated data
    ca = 0xffffffff;
    cb = 0xffffffff;
    for (i = 0; i < adlen/4; i = i+1)
    {
        encrypt_32bits(state, ((uint32_t*)ad)[i], &ciphertextword, ca, cb);
    }

    for (i = adlen & (uint64_t)0xfffffffffffffffc; i < adlen; i++)
    {
        plaintextword = ad[i];
        encrypt_8bits(state, plaintextword, &ciphertextword, ca, cb);
    }

    //256bits padding after the associated data
    acorn128_padding_256(state,cb);

    //process the plaintext
    ca = 0xffffffff;
    cb = 0;
    *mlen = clen - 16;

    for (i = 0; i < *mlen/4; i=i+1)
    {
        decrypt_32bits_fast(state, &(((uint32_t*)m)[i]), ((uint32_t*)c)[i], ca);  //&c[i], &ksword, ca, cb);
    }

    for (i = *mlen & (uint64_t)0xfffffffffffffffc; i < *mlen; i++)
    {
        ciphertextword = c[i];
        decrypt_8bits(state, &plaintextword, ciphertextword, ca, cb);
        m[i] = plaintextword;
    }

    //256 bits padding after the plaintext
    acorn128_padding_256(state,cb);

    //finalization stage, we assume that the tag length is a multiple of bytes
    acorn128_tag_generation_32bits_version(tag, state);

    for (i = 0; i  < 16; i++) check |= (tag[i] ^ c[clen - 16 + i]);
    if (check == 0) return 0;
    else return -1;
}


int Decrypt(uint8_t *block, size_t mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t adlen, uint8_t *c)
{
    return crypto_aead_decrypt(block, &mlen, c, mlen+CRYPTO_ABYTES, ad, adlen, npub, key);
}
