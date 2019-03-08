#ifndef AEGIS_COMMON_H
#define AEGIS_COMMON_H

#include "constants.h"
#include "aegis_utils.h"


// The initialization state of AEGIS
/*The input to initialization is the 128-bit key; 128-bit IV;*/
void aegis128_initialization(const uint8_t *key, const uint8_t *iv, uint8_t *state);

//the finalization state of AEGIS
void aegis128_tag_generation(uint64_t msglen, uint64_t adlen, uint8_t maclen, uint8_t *mac, uint8_t *state);

// one step of encryption
void aegis128_enc_aut_step(const uint8_t *plaintextblk, uint8_t *ciphertextblk, uint8_t *state);


#endif /* AEGIS_COMMON_H */
