#include <stdint.h>

#define maj(x,y,z)   ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)) )
#define ch(x,y,z)    ( ((x) & (y)) ^ ((~x) & (z)) )


void acorn128_initialization_32bitversion(const uint8_t *key, const uint8_t *iv, uint64_t *state);
void acorn128_tag_generation_32bits_version(uint8_t *mac, uint64_t *state);
void acorn128_padding_256(uint64_t *state, uint32_t cb);
void encrypt_32bits(uint64_t *state, uint32_t plaintextword, uint32_t *ciphertextword, uint32_t ca, uint32_t cb);
void encrypt_8bits(uint64_t *state, uint32_t plaintextword, uint32_t *ciphertextword, uint32_t ca, uint32_t cb);
