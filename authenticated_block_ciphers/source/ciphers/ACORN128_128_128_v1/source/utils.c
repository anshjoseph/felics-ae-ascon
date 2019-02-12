#include <stdint.h>

#include "utils.h"

// The initialization state of ACORN
/* The input to initialization is the 128-bit key; 128-bit IV;*/
void acorn128_initialization_32bitversion(const uint8_t *key, const uint8_t *iv, uint64_t *state)
{
        int j;
        uint32_t tem=0;

        //initialize the state to 0
        for (j = 0; j <= 6; j++) state[j] = 0;

        //run the cipher for 1792 steps
        for (j = 0;  j <= 3;  j++)
        {
            encrypt_32bits(state, ((uint32_t*)key)[j], &tem, 0xffffffff, 0xffffffff);
        }
        for (j = 4;  j <= 7;  j++)
        {
            encrypt_32bits(state, ((uint32_t*)iv)[j-4], &tem, 0xffffffff, 0xffffffff);
        }
        for (j = 8;  j <= 8; j++)
        {
            encrypt_32bits(state, ((uint32_t*)key)[j&3] ^ 1, &tem, 0xffffffff, 0xffffffff);
        }
        for (j = 9;  j <= 55; j++)
        {
            encrypt_32bits(state, ((uint32_t*)key)[j&3], &tem, 0xffffffff, 0xffffffff);
        }

}

//the finalization state of acorn
void acorn128_tag_generation_32bits_version(uint8_t *mac, uint64_t *state)
{
    int i;
    uint32_t plaintextword  = 0;
    uint32_t ciphertextword = 0;

    for (i = 0; i < 768/32; i++)
    {
        encrypt_32bits(state, plaintextword, &ciphertextword, 0xffffffff, 0xffffffff);
        if ( i >= (768/32 - 4) ) { ((uint32_t*)mac)[i-(768/32-4)] = ciphertextword; }
    }
}

// 256-bit padding after the associated data and the plaintext/ciphertext
void acorn128_padding_256(uint64_t *state, uint32_t cb)
{
    uint32_t i, plaintextword, ciphertextword, ca;

    plaintextword = 1;
    ca = 0xffffffff;
    encrypt_32bits(state, plaintextword, &ciphertextword, ca, cb);

    plaintextword = 0;
    for (i = 1; i <= 3; i++) encrypt_32bits(state, plaintextword, &ciphertextword, ca, cb);

    ca = 0;
    for (i = 4; i <= 7; i++) encrypt_32bits(state, plaintextword, &ciphertextword, ca, cb);

}

//encrypt 32 bit
void encrypt_32bits(uint64_t *state, uint32_t plaintextword, uint32_t *ciphertextword, uint32_t ca, uint32_t cb)
{
    unsigned int f,ks;
    uint64_t word_244, word_23, word_160, word_111, word_66, word_196;
    uint64_t word_12,word_235;

	word_235 = state[5] >> 5;
	word_196 = state[4] >> 3;
	word_160 = state[3] >> 6;
	word_111 = state[2] >> 4;
	word_66  = state[1] >> 5;
	word_23  = state[0] >> 23;
    word_244 = state[5] >> 14;
	word_12  = state[0] >> 12;

    //update using those 6 LFSRs
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

	//compute keystream
	ks = word_12 ^ state[3] ^ maj(word_235, state[1], state[4]) ^ ch(state[5], word_111, word_66);

	f = state[0] ^ (~state[2]) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca) ^ (cb & ks);
    *ciphertextword = plaintextword ^ ks;
	f = f ^ plaintextword;
	state[6] = state[6] ^ ( (uint64_t)f << 4 );

    //shift by 32 bits
    state[0] = (state[0] >> 32) | ((state[1] & 0xffffffff) << 29);  //32-(64-61) = 29
    state[1] = (state[1] >> 32) | ((state[2] & 0xffffffff) << 14);  //32-(64-46) = 14
    state[2] = (state[2] >> 32) | ((state[3] & 0xffffffff) << 15);  //32-(64-47) = 15
    state[3] = (state[3] >> 32) | ((state[4] & 0xffffffff) << 7);   //32-(64-39) = 7
    state[4] = (state[4] >> 32) | ((state[5] & 0xffffffff) << 5);   //32-(64-37) = 5
    state[5] = (state[5] >> 32) | ((state[6] & 0xffffffff) << 27);  //32-(64-59) = 27
    state[6] =  state[6] >> 32;

    return;
}

// encrypt 8 bits
// it is used if the length of associated data is not multiple of 32 bits;
// it is also used if the length of plaintext is not multiple of 32 bits;
void encrypt_8bits(uint64_t *state, uint32_t plaintextword, uint32_t *ciphertextword, uint32_t ca, uint32_t cb)
{
    unsigned int f,ks;
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

	state[6] ^= (state[5] ^ word_235) & 0xff;
	state[5] ^= (state[4] ^ word_196) & 0xff;
	state[4] ^= (state[3] ^ word_160) & 0xff;
	state[3] ^= (state[2] ^ word_111) & 0xff;
	state[2] ^= (state[1] ^ word_66)  & 0xff;
	state[1] ^= (state[0] ^ word_23)  & 0xff;

	ks = word_12 ^ state[3] ^ maj(word_235, state[1], state[4]) ^ ch(state[5], word_111, word_66);
    ks &= 0xff;

	f = state[0] ^ (~state[2]) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca) ^ (cb & ks);
    f  = (f ^ plaintextword) & 0xff;
	state[6] = state[6] ^ ( (uint64_t)f << 4 );

    state[0] = (state[0] >> 8) | ((state[1] & 0xff) << (29+24));   //32-(64-61) = 29
    state[1] = (state[1] >> 8) | ((state[2] & 0xff) << (14+24));   //32-(64-46) = 14
    state[2] = (state[2] >> 8) | ((state[3] & 0xff) << (15+24));   //32-(64-47) = 15
    state[3] = (state[3] >> 8) | ((state[4] & 0xff) << (7+24));    //32-(64-39) = 7
    state[4] = (state[4] >> 8) | ((state[5] & 0xff) << (5+24));    //32-(64-37) = 5
    state[5] = (state[5] >> 8) | ((state[6] & 0xff) << (27+24));    //32-(64-59) = 27
    state[6] =  state[6] >> 8;

    *ciphertextword = plaintextword ^ ks;
    return;
}
