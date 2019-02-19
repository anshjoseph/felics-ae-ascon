#ifndef AES_H
#define AES_H

#include <stdint.h>

#include "constants.h"


typedef struct {
    uint8_t roundkeys[176];
} AES_KEY;


void AES_set_encrypt_key(uint8_t *k, size_t bits, AES_KEY *key);
void AES_set_decrypt_key(uint8_t *k, size_t bits, AES_KEY *key);

void AES_encrypt(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE], AES_KEY *k);
void AES_decrypt(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE], AES_KEY *k);

#endif /* AES_H */
