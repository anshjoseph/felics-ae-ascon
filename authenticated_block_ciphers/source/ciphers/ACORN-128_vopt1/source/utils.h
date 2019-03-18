#include <stdint.h>


#define maj(x,y,z)   ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)) )
#define ch(x,y,z)    ( ((x) & (y)) ^ ((~x) & (z)) )

//encrypt 32 bit
void encrypt_32bits(uint64_t *state, uint32_t plaintextword, uint32_t *ciphertextword, uint32_t ca, uint32_t cb);

// encrypt 32 bit;
// used when cb = 0; so we can remove the operation (cb * ks)
void encrypt_32bits_fast(uint64_t *state, uint32_t plaintextword, uint32_t *ciphertextword, uint32_t ca);

// encrypt 8 bits
// it is used if the length of associated data is not multiple of 32 bits;
// it is also used if the length of plaintext is not multiple of 32 bits;
void encrypt_8bits(uint64_t *state, uint32_t plaintextword, uint32_t *ciphertextword, uint32_t ca, uint32_t cb);

// 256-bit padding after the associated data and the plaintext/ciphertext
void acorn128_padding_256(uint64_t *state, uint32_t cb);

//the finalization state of acorn
void acorn128_tag_generation_32bits_version(uint8_t *mac, uint64_t *state);

// The initialization state of ACORN
/* The input to initialization is the 128-bit key; 128-bit IV;*/
void acorn128_initialization_32bitversion(const uint8_t *key, const uint8_t *iv, uint64_t *state);
