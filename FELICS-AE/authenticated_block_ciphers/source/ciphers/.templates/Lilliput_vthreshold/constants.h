#ifndef CONSTANTS_H
#define CONSTANTS_H

#include "data_types.h"
#include "parameters.h"


#define BLOCK_SIZE BLOCK_BYTES
#define KEY_SIZE KEY_BYTES

#define CRYPTO_NPUBBYTES NONCE_BYTES
#define CRYPTO_ABYTES TAG_BYTES


/*
 *
 * Cipher constants
 *
 */
extern ROM_DATA_BYTE PERMUTATIONS[2][BLOCK_BYTES];
extern SBOX_BYTE S[256];

extern ROM_DATA_BYTE F[16][16];
extern ROM_DATA_BYTE G[4][16];
extern ROM_DATA_BYTE Q[8][16];
extern ROM_DATA_BYTE P[16];

enum permutation
{
    PERMUTATION_ENCRYPTION = 0, /* PI(i) */
    PERMUTATION_DECRYPTION = 1, /* PI^-1(i) */
    PERMUTATION_NONE
};

typedef enum permutation permutation;


#endif /* CONSTANTS_H */
