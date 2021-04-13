#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "forkskinny.h"
#include "extra_api.h"
#include "skinny_round.h"
#include "helpers.h"




//#define DEBUG_FORK


/* === Print intermediate results for debugging purposes === */
/*void print_fork(unsigned char s[4][4]){
    #ifdef DEBUG_FORK
    int j,k;
    printf("\n === At the fork: ");
    for (j = 0; j < 4; j++)
        for (k = 0; k < 4; k++)
            printf("%02x ", s[j][k]);
    printf(" ===");
    #endif
}*/
/////////////////////helpers///////////////////////////////////////////
void stateCopy(unsigned char a[4][4], unsigned char b[4][4]){
    int i, j;

    for(i = 0; i < 4; i++)
        for(j = 0; j <  4; j++)
            a[i][j] = b[i][j];
}

void tweakeyCopy(unsigned char tweakey[TWEAKEY_BLOCKSIZE_RATIO][4][4], unsigned char input[TWEAKEY_BLOCKSIZE_RATIO][4][4]){
    int i, j, k;

    for(k = 0; k < TWEAKEY_BLOCKSIZE_RATIO; k++)
        for(i = 0; i < 4; i++)
            for(j = 0; j < 4; j++)
                tweakey[k][i][j]=input[k][i][j];
}

void stateToCharArray(unsigned char* array, unsigned char state[4][4]){

    int i;

    #ifdef CRYPTO_BLOCKSIZE_8
    for(i = 0; i < 8; i++)
        array[i] = ((state[(2*i)>>2][(2*i)&0x3] & 0xF) << 4) | (state[(2*i+1)>>2][(2*i+1)&0x3] & 0xF);
    #endif
    #ifdef CRYPTO_BLOCKSIZE_16
    for(i = 0; i < 16; i++)
        array[i] = state[i>>2][i&0x3] & 0xFF;
    #endif

}


///////////////////////////////skinny round.c////////////////////////////////////////

//#define DEBUG_SKINNY

/* === Print intermediate results for debugging purposes === */
/*void print_cells(unsigned char s[4][4], int i){
    #ifdef DEBUG_SKINNY
    int j,k;
    printf("\nAfter round %i: ", i);
    for (j = 0; j < 4; j++)
        for (k = 0; k < 4; k++)
            printf("%02x ", s[j][k]);
    #endif
}*/

// Packing of data is done as follows (state[i][j] stands for row i and column j):
// 0  1  2  3
// 4  5  6  7
// 8  9 10 11
//12 13 14 15

/* SBox */
#ifdef CRYPTO_BLOCKSIZE_8
const unsigned char sbox[16] = {12,6,9,0,1,10,2,11,3,8,5,13,4,14,7,15};
const unsigned char sbox_inv[16] = {3,4,6,8,12,10,1,14,9,2,5,7,0,11,13,15};
#endif

#ifdef CRYPTO_BLOCKSIZE_16
const unsigned char sbox[256] = {0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b,0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b,0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9,0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d, 0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d,0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd,0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed, 0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd,0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb,0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f, 0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f,0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff};
const unsigned char sbox_inv[256] = {0xac, 0xe8, 0x68, 0x3c, 0x6c, 0x38, 0xa8, 0xec, 0xaa, 0xae, 0x3a, 0x3e, 0x6a, 0x6e, 0xea, 0xee,0xa6, 0xa3, 0x33, 0x36, 0x66, 0x63, 0xe3, 0xe6, 0xe1, 0xa4, 0x61, 0x34, 0x31, 0x64, 0xa1, 0xe4,0x8d, 0xc9, 0x49, 0x1d, 0x4d, 0x19, 0x89, 0xcd, 0x8b, 0x8f, 0x1b, 0x1f, 0x4b, 0x4f, 0xcb, 0xcf,0x85, 0xc0, 0x40, 0x15, 0x45, 0x10, 0x80, 0xc5, 0x82, 0x87, 0x12, 0x17, 0x42, 0x47, 0xc2, 0xc7,0x96, 0x93, 0x03, 0x06, 0x56, 0x53, 0xd3, 0xd6, 0xd1, 0x94, 0x51, 0x04, 0x01, 0x54, 0x91, 0xd4,0x9c, 0xd8, 0x58, 0x0c, 0x5c, 0x08, 0x98, 0xdc, 0x9a, 0x9e, 0x0a, 0x0e, 0x5a, 0x5e, 0xda, 0xde,0x95, 0xd0, 0x50, 0x05, 0x55, 0x00, 0x90, 0xd5, 0x92, 0x97, 0x02, 0x07, 0x52, 0x57, 0xd2, 0xd7,0x9d, 0xd9, 0x59, 0x0d, 0x5d, 0x09, 0x99, 0xdd, 0x9b, 0x9f, 0x0b, 0x0f, 0x5b, 0x5f, 0xdb, 0xdf,0x16, 0x13, 0x83, 0x86, 0x46, 0x43, 0xc3, 0xc6, 0x41, 0x14, 0xc1, 0x84, 0x11, 0x44, 0x81, 0xc4,0x1c, 0x48, 0xc8, 0x8c, 0x4c, 0x18, 0x88, 0xcc, 0x1a, 0x1e, 0x8a, 0x8e, 0x4a, 0x4e, 0xca, 0xce,0x35, 0x60, 0xe0, 0xa5, 0x65, 0x30, 0xa0, 0xe5, 0x32, 0x37, 0xa2, 0xa7, 0x62, 0x67, 0xe2, 0xe7,0x3d, 0x69, 0xe9, 0xad, 0x6d, 0x39, 0xa9, 0xed, 0x3b, 0x3f, 0xab, 0xaf, 0x6b, 0x6f, 0xeb, 0xef,0x26, 0x23, 0xb3, 0xb6, 0x76, 0x73, 0xf3, 0xf6, 0x71, 0x24, 0xf1, 0xb4, 0x21, 0x74, 0xb1, 0xf4,0x2c, 0x78, 0xf8, 0xbc, 0x7c, 0x28, 0xb8, 0xfc, 0x2a, 0x2e, 0xba, 0xbe, 0x7a, 0x7e, 0xfa, 0xfe,0x25, 0x70, 0xf0, 0xb5, 0x75, 0x20, 0xb0, 0xf5, 0x22, 0x27, 0xb2, 0xb7, 0x72, 0x77, 0xf2, 0xf7,0x2d, 0x79, 0xf9, 0xbd, 0x7d, 0x29, 0xb9, 0xfd, 0x2b, 0x2f, 0xbb, 0xbf, 0x7b, 0x7f, 0xfb, 0xff};
#endif

/* ShiftRows and TweakeySchedule permutations */
const unsigned char P[16] = {0,1,2,3,7,4,5,6,10,11,8,9,13,14,15,12};
const unsigned char TWEAKEY_P[16] = {9,15,8,13,10,14,12,11,0,1,2,3,4,5,6,7};

/* 7-bit round constant */
const unsigned char RC[87] = {0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7e, 0x7d, 0x7b, 0x77, 0x6f, 0x5f, 0x3e, 0x7c, 0x79, 0x73, 0x67, 0x4f, 0x1e, 0x3d, 0x7a, 0x75, 0x6b, 0x57, 0x2e, 0x5c, 0x38, 0x70, 0x61, 0x43, 0x06, 0x0d, 0x1b, 0x37, 0x6e, 0x5d, 0x3a, 0x74, 0x69, 0x53, 0x26, 0x4c, 0x18, 0x31, 0x62, 0x45, 0x0a, 0x15, 0x2b, 0x56, 0x2c, 0x58, 0x30, 0x60, 0x41, 0x02, 0x05, 0x0b, 0x17, 0x2f, 0x5e, 0x3c, 0x78, 0x71, 0x63, 0x47, 0x0e, 0x1d, 0x3b, 0x76, 0x6d, 0x5b, 0x36, 0x6c, 0x59, 0x32, 0x64, 0x49, 0x12, 0x25, 0x4a, 0x14, 0x29, 0x52, 0x24, 0x48, 0x10};



void AddConstants(unsigned char state[4][4], int i){
	state[0][0] ^= (RC[i] & 0xf); // 4-3-2-1
	state[1][0] ^= ((RC[i]>>4) & 0x7); // 7-6-5
	state[2][0] ^= 0x2;

    /* Indicate tweak material */
    state[0][2] ^= 0x2;
}

void SubCell(unsigned char state[4][4]){
    int i,j;
    for(i = 0; i < 4; i++)
        for(j = 0; j <  4; j++)
            state[i][j] = sbox[state[i][j]];
}

void SubCell_inv(unsigned char state[4][4]){
    int i,j;
    for(i = 0; i < 4; i++)
        for(j = 0; j <  4; j++)
            state[i][j] = sbox_inv[state[i][j]];
}

void ShiftRows(unsigned char state[4][4]){
	int i, j, pos;
	unsigned char state_tmp[4][4];

    for(i = 0; i < 4; i++)
        for(j = 0; j < 4; j++){
            pos=P[j+4*i];
            state_tmp[i][j]=state[pos>>2][pos&0x3];
        }
    stateCopy(state, state_tmp);
}

void ShiftRows_inv(unsigned char state[4][4]){
	int i, j, pos;
	unsigned char state_tmp[4][4];

    for(i = 0; i < 4; i++)
        for(j = 0; j < 4; j++){
            pos=P[j+4*i];
            state_tmp[pos>>2][pos&0x3]=state[i][j];
        }
    stateCopy(state, state_tmp);
}

void MixColumn(unsigned char state[4][4]){
	int j;
    unsigned char temp;

	for(j = 0; j < 4; j++){
        state[1][j]^=state[2][j];
        state[2][j]^=state[0][j];
        state[3][j]^=state[2][j];
        temp=state[3][j];

        state[3][j]=state[2][j];
        state[2][j]=state[1][j];
        state[1][j]=state[0][j];
        state[0][j]=temp;
	}
}

void MixColumn_inv(unsigned char state[4][4]){
	int j;
    unsigned char temp;

	for(j = 0; j < 4; j++){
        temp=state[3][j];
        state[3][j]=state[0][j];
        state[0][j]=state[1][j];
        state[1][j]=state[2][j];
        state[2][j]=temp;

        state[3][j]^=state[2][j];
        state[2][j]^=state[0][j];
        state[1][j]^=state[2][j];
	}
}



/* ADVANCE THE KEY SCHEDULE ONCE */
void advanceKeySchedule(unsigned char keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4])
{
    /* Declarations */
	int i, j, k;
	unsigned char pos;
	unsigned char keyCells_tmp[TWEAKEY_BLOCKSIZE_RATIO][4][4];

    // update the subtweakey states with the permutation
    for(k = 0; k < TWEAKEY_BLOCKSIZE_RATIO; k++){
        for(i = 0; i < 4; i++){ 
            for(j = 0; j < 4; j++){
                pos=TWEAKEY_P[j+4*i];
                keyCells_tmp[k][i][j]=keyCells[k][pos>>2][pos&0x3];
            }
        }
    }

    // update the subtweakey states with the LFSRs
    for(k = 1; k < TWEAKEY_BLOCKSIZE_RATIO; k++)
        for(i = 0; i < 2; i++) // LFSR only on upper two rows
            for(j = 0; j < 4; j++){
                if (k==1){ // TK2
                    #ifdef CRYPTO_BLOCKSIZE_8
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xE)^((keyCells_tmp[k][i][j]>>3)&0x1)^((keyCells_tmp[k][i][j]>>2)&0x1);
                    #else 
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xFE)^((keyCells_tmp[k][i][j]>>7)&0x01)^((keyCells_tmp[k][i][j]>>5)&0x01);
                    #endif 
                }
                else if (k==2){ // TK3
                    #ifdef CRYPTO_BLOCKSIZE_8
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7)^((keyCells_tmp[k][i][j])&0x8)^((keyCells_tmp[k][i][j]<<3)&0x8);
                    #else 
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7F)^((keyCells_tmp[k][i][j]<<7)&0x80)^((keyCells_tmp[k][i][j]<<1)&0x80);
                    #endif 
                }
            }

    tweakeyCopy(keyCells, keyCells_tmp);

}

/* REVERSE THE KEY SCHEDULE ONCE (used in decryption and reconstruction) */
void reverseKeySchedule(unsigned char keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4]){
	unsigned char keyCells_tmp[TWEAKEY_BLOCKSIZE_RATIO][4][4];
	int i, j, k;
	unsigned char pos;

    // update the subtweakey states with the permutation
    for(k = 0; k <TWEAKEY_BLOCKSIZE_RATIO; k++)
        for(i = 0; i < 4; i++)
            for(j = 0; j < 4; j++){
                // application of the inverse TWEAKEY permutation
                pos=TWEAKEY_P[j+4*i];
                keyCells_tmp[k][pos>>2][pos&0x3]=keyCells[k][i][j];
            }

    // update the subtweakey states with the LFSRs
    for(k = 1; k <TWEAKEY_BLOCKSIZE_RATIO; k++)
        for(i = 2; i < 4; i++)
            for(j = 0; j < 4; j++){
                if (k==1){
                    #ifdef CRYPTO_BLOCKSIZE_8
                    if (CRYPTO_BLOCKSIZE == 8)
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7)^((keyCells_tmp[k][i][j]<<3)&0x8)^((keyCells_tmp[k][i][j])&0x8);
                    #else
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7F)^((keyCells_tmp[k][i][j]<<7)&0x80)^((keyCells_tmp[k][i][j]<<1)&0x80);
                    #endif
                }
                else if (k==2){
                    #ifdef CRYPTO_BLOCKSIZE_8
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xE)^((keyCells_tmp[k][i][j]>>3)&0x1)^((keyCells_tmp[k][i][j]>>2)&0x1);
                    #else
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xFE)^((keyCells_tmp[k][i][j]>>7)&0x01)^((keyCells_tmp[k][i][j]>>5)&0x01);
                    #endif
                }
            }
    tweakeyCopy(keyCells, keyCells_tmp);
}


// Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state
void AddKey(unsigned char state[4][4], unsigned char keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4]){

	int i, j, k;
    for (k = 0; k < TWEAKEY_BLOCKSIZE_RATIO; k++) 
        for(i = 0; i < 2; i++) // Row i (two rows only)
            for(j = 0; j < 4; j++) // Cell j in row i
                state[i][j] ^= keyCells[k][i][j]; 

    advanceKeySchedule(keyCells);
}

// Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state (inverse function}
void AddKey_inv(unsigned char state[4][4], unsigned char keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4]){

    int i,j,k;
    reverseKeySchedule(keyCells);

    for (k = 0; k < TWEAKEY_BLOCKSIZE_RATIO; k++)  // For every TKi
        for(i = 0; i < 2; i++) // Row i (two rows only)
            for(j = 0; j < 4; j++) // Cell j in row i
                state[i][j] ^= keyCells[k][i][j]; 
}

void skinny_round(unsigned char state[4][4], unsigned char keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4], int i){

    SubCell(state);
    AddConstants(state, i);
    AddKey(state, keyCells);
    ShiftRows(state);
    MixColumn(state);

    //print_cells(state, i);
}

void skinny_round_inv(unsigned char state[4][4], unsigned char keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4], int i){

    MixColumn_inv(state);
    ShiftRows_inv(state);
    AddKey_inv(state, keyCells);
    AddConstants(state, i);
    SubCell_inv(state);

    //print_cells(state, i);
}
//////////////////////////////////paef.c////////////////////////////////////////////////

//#define DEBUG_PAEF
#define MAX_COUNTER_BITS ((((CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES) << 3) - 3))

/*void print_tweakey(unsigned char* tweakey, int i){
    #ifdef DEBUG_PAEF
    int j;
    printf("\nTweakey at block %i: ", i);
    for (j = 0; j < CRYPTO_TWEAKEYSIZE; j++)
            printf("%02x ", tweakey[j]);
    printf("\n");
    #endif
}

void print_running_tag(unsigned char* running_tag, int i){
    #ifdef DEBUG_PAEF
    int j;
    printf("\nRunning tag after block %i: ", i);
    for (j = 0; j < CRYPTO_BLOCKSIZE; j++)
            printf("%02x ", running_tag[j]);
    printf("\n");
    #endif
}

void print_plain_cipher(unsigned char* state, int i){
    #ifdef DEBUG_PAEF
    int j;
    printf("\nBlock %i of plaintext/ciphertext: ", i);
    for (j = 0; j < CRYPTO_BLOCKSIZE; j++)
            printf("%02x ", state[j]);
    printf("\n");
    #endif
}*/

int paef_encrypt(
    unsigned char *c,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, // nonce, of which the length is specified in api.h
    const unsigned char *k) { // key, of which the length is specified in api.h

    /* Declarations */
    uint64_t i, j;
    unsigned char A_j[CRYPTO_BLOCKSIZE], M_j[CRYPTO_BLOCKSIZE];
    unsigned char C0[CRYPTO_BLOCKSIZE], C1[CRYPTO_BLOCKSIZE];
    unsigned char tweakey[TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE];
    unsigned char running_tag[CRYPTO_BLOCKSIZE];

    uint64_t nbABlocks = adlen / CRYPTO_BLOCKSIZE;
    uint64_t nbMBlocks = mlen / CRYPTO_BLOCKSIZE;

    unsigned char AD[(nbABlocks+1)*CRYPTO_BLOCKSIZE], M[(nbMBlocks+1)*CRYPTO_BLOCKSIZE]; /* Allocate one more block in case padding is needed */

    
    uint64_t last_m_block_size = mlen % CRYPTO_BLOCKSIZE;
    uint8_t ad_incomplete = (adlen != nbABlocks*CRYPTO_BLOCKSIZE) | ((adlen == 0) & (mlen == 0));  /* Boolean flag to indicate whether the final block is complete */
    uint8_t m_incomplete = (last_m_block_size != 0);  /* Boolean flag to indicate whether the final block is complete */

    /* Check if ad length not too large */
    if ((uint64_t)(adlen / (uint64_t) CRYPTO_BLOCKSIZE) > (uint64_t) ((uint64_t)1 << MAX_COUNTER_BITS)){
        printf("Error: AD too long! Terminating. \n");
        return -1;
    }

    /* Check if message length not too large */
    if ((uint64_t)(mlen / (uint64_t) CRYPTO_BLOCKSIZE) > (uint64_t) ((uint64_t)1 << MAX_COUNTER_BITS)){
       // printf("Error: M too long! Terminating. \n");
        return -1;
    }

    memset(running_tag, 0, CRYPTO_BLOCKSIZE); /* Set running tag to zero */

    /* Padding of A */
    for (i = 0; i < adlen; i++)
        AD[i] = ad[i]; 

    /* Pad A if it is incomplete OR if it is empty and there is no message either*/
    if (ad_incomplete)
        nbABlocks++;

    AD[adlen] = 0x80;

    for (i = adlen+1; i < nbABlocks*CRYPTO_BLOCKSIZE; i++) 
        AD[i] = 0x00; 

    /* Pad M if it is incomplete */
    if (last_m_block_size != 0)
        nbMBlocks++;

    for (i = 0; i < mlen; i++)
        M[i] = m[i]; 

    M[mlen] = 0x80;

    for (i = mlen+1; i < nbMBlocks*CRYPTO_BLOCKSIZE; i++)
        M[i] = 0x00;


    /* Construct baseline tweakey: key and nonce part remains unchanged throughout the execution. Initialize the remainder of the tweakey state to zero. */
    
    // Key
    for (i = 0; i < CRYPTO_KEYBYTES; i++)
        tweakey[i] = k[i]; 
    
    // Nonce
    for (i = 0; i < CRYPTO_NPUBBYTES; i++)
        tweakey[CRYPTO_KEYBYTES+i] = npub[i]; 

    // Flags and counter to zero
    for (i = 0; i < CRYPTO_TWEAKEYSIZE-CRYPTO_KEYBYTES-CRYPTO_NPUBBYTES; i++) {
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES+i] = 0; 
    }

    // For ForkSkinny-128-192 and ForkSkinny-128-288, the tweakey state needs to be zero-padded.
    for (i = CRYPTO_TWEAKEYSIZE; i < TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE; i++)
        tweakey[i] = 0; 

    /* Processing associated data */
    //#ifdef DEBUG_PAEF
    //printf("\n/* Processing associated data */ \n");
    //#endif
    
    for (j = 1; j <= nbABlocks; j++) {

        /* Load next block */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            A_j[i] = AD[(j-1)*CRYPTO_BLOCKSIZE+i];

        /* Tweakey flags */
        if ((j==nbABlocks) & ad_incomplete)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x60; // Flag 011

        else if (j==nbABlocks)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x20; // Flag 001

        else
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x00; // Flag 000
            
        /* Counter */
        for (i = 1; i < CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES; i++)
            tweakey[CRYPTO_TWEAKEYSIZE-i] = (j >> 8*(i-1)) & 0xff;
        
        /* Special treatment for the tweak byte that is shared between the counter and the flags */
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] ^= (j >> 8*(CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES-1)) & 0xff;

        //print_tweakey(tweakey, j);

        /* ForkEncrypt */
        forkEncrypt(C0, C1, A_j, tweakey, ENC_C1);

        /* Update running tag */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            running_tag[i] ^= C1[i];

        //print_running_tag(running_tag, j);
    }

    if (mlen == 0) /* If message is empty, copy tag to output buffer */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            c[i] = running_tag[i];

    /* Processing message */
   // #ifdef DEBUG_PAEF
     //   printf("\n/* Processing message */\n");
    //#endif
    
    for (j = 1; j <= nbMBlocks; j++) {

        /* Load next block */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            M_j[i] = M[(j-1)*CRYPTO_BLOCKSIZE+i];

        /* Tweakey flags */
        if ((j==nbMBlocks) & m_incomplete)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0xE0; // Flag 111
        
        else if (j==nbMBlocks)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0xA0; // Flag 101

        else
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x80; // Flag 100
            
        /* Counter */
        for (i = 1; i < CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES; i++)
            tweakey[CRYPTO_TWEAKEYSIZE-i] = (j >> 8*(i-1)) & 0xff;
        
        /* Special treatment for the tweak byte that is shared between the counter and the flags */
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] ^= (j >> 8*(CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES-1)) & 0xff;

        //print_tweakey(tweakey, j);

        /* ForkEncrypt */
        forkEncrypt(C0, C1, M_j, tweakey, ENC_BOTH);

        /* Final incomplete block */
        if ((j==nbMBlocks) & m_incomplete){
            /* Add running tag to C0 and move to ciphertext output */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) 
                c[(j-1)*CRYPTO_BLOCKSIZE+i] = C0[i] ^ running_tag[i];

            /* C1 now contains the tag. Move it to ciphertext output */
            for (i = 0; i < last_m_block_size; i++)
                c[mlen+CRYPTO_BLOCKSIZE-last_m_block_size+i] = C1[i];

            //print_plain_cipher(c, j);
            //print_running_tag(C1, j);
        }

        /* Final complete block */
        else if (j==nbMBlocks){
            /* Add running tag to C0 and move to ciphertext output */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) 
                c[(j-1)*CRYPTO_BLOCKSIZE+i] = C0[i] ^ running_tag[i];

            /* C1 now contains the tag. Move it to ciphertext output */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) 
                c[mlen+i] = C1[i];

           // print_plain_cipher(c, j);
            //print_running_tag(C1, j);
        }

        /* Non-final block */
        else{
            /* C0 contains ciphertext block. Move it to ciphertext output */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
                c[(j-1)*CRYPTO_BLOCKSIZE+i] = C0[i];

            /* Update running tag with C1 value */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
                running_tag[i] ^= C1[i];

           // print_plain_cipher(C0, j);
            //print_running_tag(running_tag, j);
        }

    }

    return 0; // all is well
}


int paef_decrypt(
	unsigned char *m,
	const unsigned char *c,unsigned long long clen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k){


    /* Declarations */
    uint64_t i,j;
    uint8_t res = 0;
    unsigned char running_tag[CRYPTO_BLOCKSIZE];
    unsigned char tweakey[TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE];
    unsigned char P[CRYPTO_BLOCKSIZE], C0[CRYPTO_BLOCKSIZE], C1[CRYPTO_BLOCKSIZE];

    uint64_t nbABlocks = adlen / CRYPTO_BLOCKSIZE;
    uint64_t nbMBlocks = clen / CRYPTO_BLOCKSIZE - 1;
    
    unsigned char A_j[CRYPTO_BLOCKSIZE], C_j[CRYPTO_BLOCKSIZE];
    unsigned char AD[(nbABlocks+1) * CRYPTO_BLOCKSIZE]; /* Allocate one more block in case padding is needed */

    uint8_t ad_incomplete = (adlen != nbABlocks*CRYPTO_BLOCKSIZE) | ((adlen == 0) & (clen == CRYPTO_BLOCKSIZE));  /* Boolean flag to indicate whether the final block is complete */
    uint8_t c_incomplete = (clen % CRYPTO_BLOCKSIZE != 0);  /* Boolean flags to indicate whether the final block is complete */
    uint64_t last_c_block_size = clen % CRYPTO_BLOCKSIZE;


    /* Check if ad length not too large */
    if ((uint64_t)(adlen / (uint64_t) CRYPTO_BLOCKSIZE) > (uint64_t) ((uint64_t)1 << MAX_COUNTER_BITS)){
        //printf("Error: AD too long! Terminating. \n");
        return -1;
    }

    /* Check if message length not too large */
    if ((uint64_t)((uint64_t)(clen - (uint64_t) CRYPTO_BLOCKSIZE) / (uint64_t) CRYPTO_BLOCKSIZE) > (uint64_t) ((uint64_t)1 << MAX_COUNTER_BITS)){
       // printf("Error: M too long! Terminating. \n");
        return -1;
    }

    memset(running_tag, 0, CRYPTO_BLOCKSIZE); /* Set running tag to zero */

    /* Padding of A */
    for (i = 0; i < adlen; i++)
        AD[i] = ad[i]; 
    
    /* Pad A if it is incomplete OR if it is empty and there is no message either*/
    if (ad_incomplete)
        nbABlocks++;

    AD[adlen] = 0x80;

    for (i = adlen+1; i < nbABlocks*CRYPTO_BLOCKSIZE; i++)
        AD[i] = 0x00; 

    /* Message was padded */
    if (c_incomplete)
        nbMBlocks++; 

    /* Construct baseline tweakey: key and nonce part remains unchanged throughout the execution. Initialize the remainder of the tweakey state to zero. */
    
    // Key
    for (i = 0; i < CRYPTO_KEYBYTES; i++)
        tweakey[i] = k[i]; 
    
    // Nonce
    for (i = 0; i < CRYPTO_NPUBBYTES; i++)
        tweakey[CRYPTO_KEYBYTES+i] = npub[i]; 

    // Flags and counter to zero
    for (i = 0; i < CRYPTO_TWEAKEYSIZE-CRYPTO_KEYBYTES-CRYPTO_NPUBBYTES; i++)
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES+i] = 0; 

    // For ForkSkinny-128-192 and ForkSkinny-128-288, the tweakey state needs to be zero-padded.
    for (i = CRYPTO_TWEAKEYSIZE; i < TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE; i++)
        tweakey[i] = 0; 

    /* Processing associated data */
   //#ifdef DEBUG_PAEF
    //printf("\n/* Processing associated data */\n");
    //#endif
    
    for (j = 1; j <= nbABlocks; j++) {

        /* Load next block */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            A_j[i] = AD[(j-1)*CRYPTO_BLOCKSIZE+i];

        /* Tweakey flags */
        if ((j==nbABlocks) & ad_incomplete)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x60; // Flag 011

        else if (j==nbABlocks)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x20; // Flag 001
        
        else
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x00; // Flag 000
        
        /* Counter */
        for (i = 1; i < CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES; i++) 
            tweakey[CRYPTO_TWEAKEYSIZE-i] = (j >> 8*(i-1)) & 0xff;
        
        
        /* Special treatment for the tweak byte that is shared between the counter and the flags */
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] ^= (j >> 8*(CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES-1)) & 0xff;

        //print_tweakey(tweakey, j);

        /* ForkEncrypt */
        forkEncrypt(C0, C1, A_j, tweakey, ENC_C1);

        /* Update running tag */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            running_tag[i] ^= C1[i];

        //print_running_tag(running_tag, j);
    }

    if (clen == CRYPTO_BLOCKSIZE) /* If message is empty, copy tag to output buffer */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            C1[i] = running_tag[i];

    /* Process ciphertext */
   // #ifdef DEBUG_PAEF
     //   printf("\n/* Processing ciphertext */\n");
   // #endif
    
    for (j = 1; j <= nbMBlocks; j++) {
        
        /* Final ciphertext block: XOR with running tag*/
        if (j==nbMBlocks)
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
                C_j[i] = c[(j-1)*CRYPTO_BLOCKSIZE+i] ^ running_tag[i]; // C0 is running tag xor C*
        
        /* Non-final ciphertext block*/
        else 
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
                C_j[i] = c[(j-1)*CRYPTO_BLOCKSIZE+i];

        /* Tweakey flags */
        if ((j==nbMBlocks) & c_incomplete)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0xE0; // Flag 111
        
        else if (j==nbMBlocks)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0xA0; // Flag 101
        
        else 
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x80; // Flag 100
        
            
        /* Counter */
        for (i = 1; i < CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES; i++)
            tweakey[CRYPTO_TWEAKEYSIZE-i] = (j >> 8*(i-1)) & 0xff;
        
        /* Special treatment for the tweak byte that is shared between the counter and the flags */
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] ^= (j >> 8*(CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES-1)) & 0xff;

        //print_tweakey(tweakey, j);

        /* ForkInvert */
        forkInvert(P, C1, C_j, tweakey, 0, INV_BOTH);

        /* Final incomplete block */
        if ((j==nbMBlocks) & c_incomplete)
            for (i = 0; i < last_c_block_size; i++) // Move incomplete P to plaintext output
                m[(j-1)*CRYPTO_BLOCKSIZE+i] = P[i];
        
        /* Final block */
        else if (j==nbMBlocks)
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) // Move complete P to plaintext output
                m[(j-1)*CRYPTO_BLOCKSIZE+i] = P[i];
        
        else{
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) // Move complete P to plaintext output
                m[(j-1)*CRYPTO_BLOCKSIZE+i] = P[i];

            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) // Add C1 to running tag
                running_tag[i] ^= C1[i];
        }

        //print_plain_cipher(P, j);
        //print_running_tag(running_tag, j);
    }
 
    /* Check if the tag (C1) is correct, if incorrect output error (denoted by -1) */

    /* Does the tag part match? */
    if (c_incomplete){
        for (i = 0; i < last_c_block_size; i++)
            if (C1[i] != c[clen-last_c_block_size+i]){
                res = -1;
            }
    }
    else{
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            if (C1[i] != c[clen-CRYPTO_BLOCKSIZE+i]){
                res = -1;
            }
    }
    /* If incomplete: does the plaintext redundancy match? */
    if (c_incomplete){
        if (P[last_c_block_size] != 0x80){
            res = -1;
        }
        for (i = 1; i < CRYPTO_BLOCKSIZE-last_c_block_size; i++)
            if (P[last_c_block_size+i] != 0x00){
                res = -1;
            }
        }
            
    return res;
}


/////////////////////////////////forkeskinny//////////////////////////////////////
void AddBranchConstant(unsigned char state[4][4]){
	int i, j;
    #ifdef CRYPTO_BLOCKSIZE_8
    const unsigned char BC[16] = {0x01,0x02,0x04,0x09,0x03,0x06,0x0d,0x0a,0x05,0x0b,0x07,0x0f,0x0e,0x0c,0x08,0x01};
    #else
    const unsigned char BC[16] = {0x01,0x02,0x04,0x08,0x10,0x20,0x41,0x82,0x05,0x0a,0x14,0x28,0x51,0xa2,0x44,0x88};
    #endif

    for(i = 0; i < 4; i++)
        for(j = 0; j < 4; j++){
            state[i][j] ^= BC[4*i+j];
        }
}

void loadStateAndKey(unsigned char state[4][4], unsigned char keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4], unsigned char* input, const unsigned char* userkey){

    int i;

	for(i = 0; i < 16; i++) {
        #ifdef CRYPTO_BLOCKSIZE_8
            // For BS = 64, cells are only half-bytes so every input byte needs to be spread over two cells
            if(i&1){
                state[i>>2][i&0x3] = input[i>>1]&0xF;
                keyCells[0][i>>2][i&0x3] = userkey[i>>1]&0xF;
                if (TWEAKEY_BLOCKSIZE_RATIO >= 2)
                    keyCells[1][i>>2][i&0x3] = userkey[(i+16)>>1]&0xF;
                if (TWEAKEY_BLOCKSIZE_RATIO >= 3)
                    keyCells[2][i>>2][i&0x3] = userkey[(i+32)>>1]&0xF;
            }
            else {
                state[i>>2][i&0x3] = (input[i>>1]>>4)&0xF;
                keyCells[0][i>>2][i&0x3] = (userkey[i>>1]>>4)&0xF;
                if (TWEAKEY_BLOCKSIZE_RATIO >= 2)
                    keyCells[1][i>>2][i&0x3] = (userkey[(i+16)>>1]>>4)&0xF;
                if (TWEAKEY_BLOCKSIZE_RATIO >= 3)
                    keyCells[2][i>>2][i&0x3] = (userkey[(i+32)>>1]>>4)&0xF;
            }
        #else
            state[i>>2][i&0x3] = input[i]&0xFF;
            keyCells[0][i>>2][i&0x3] = userkey[i]&0xFF;
            if (TWEAKEY_BLOCKSIZE_RATIO >= 2)
                keyCells[1][i>>2][i&0x3] = userkey[i+16]&0xFF;
            if (TWEAKEY_BLOCKSIZE_RATIO >= 3)
                keyCells[2][i>>2][i&0x3] = userkey[i+32]&0xFF;
        #endif
    }
}

void forkEncrypt(unsigned char* C0, unsigned char* C1, unsigned char* input, const unsigned char* userkey, const enum encrypt_selector s){

	unsigned char state[4][4], L[4][4], keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4]; 
    int i;

    loadStateAndKey(state, keyCells, input, userkey);

    /* Before fork */
	for(i = 0; i < CRYPTO_NBROUNDS_BEFORE; i++)
        skinny_round(state, keyCells, i);

    /* Save fork if both output blocks are needed */
    if (s == ENC_BOTH)
        stateCopy(L, state);

    //print_fork(state);

    /* Right branch (C1) */
    if ((s == ENC_C1) | (s == ENC_BOTH)){
        for(i = CRYPTO_NBROUNDS_BEFORE; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++) 
            skinny_round(state, keyCells, i);

        /* Move result to output buffer*/
        stateToCharArray(C1, state);
    }

    /* Reinstall L as state if necessary */
    if (s == ENC_BOTH)
        stateCopy(state, L);

    /* Left branch (C0) */
    if ((s == ENC_C0) | (s == ENC_BOTH)){

        /* Add branch constant */
        AddBranchConstant(state);

        for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++) 
            skinny_round(state, keyCells, i);

        /* Move result to output buffer */
        stateToCharArray(C0, state);
    }

    /* Null pointer for invalid outputs */
    if (s == ENC_C0) 
        C1 = NULL;
    else if (s == ENC_C1) 
        C0 = NULL;

}


void forkInvert(unsigned char* inverse, unsigned char* C_other, unsigned char* input, const unsigned char* userkey, uint8_t b, const enum inversion_selector s){

	unsigned char state[4][4], L[4][4], keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4];
	int i;

    loadStateAndKey(state, keyCells, input, userkey);

    if (b == 1){

        /* Advance the key schedule in order to decrypt */
        for(i = 0; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++)
            advanceKeySchedule(keyCells);

        /* From C1 to fork*/
        for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER-1; i >= CRYPTO_NBROUNDS_BEFORE; i--)
            skinny_round_inv(state, keyCells, i);

        /* Save fork if both blocks are needed */
        if (s == INV_BOTH) 
            stateCopy(L, state);

        //print_fork(state);

        if ((s == INV_INVERSE) | (s == INV_BOTH)) {
            /* From fork to M */
            for(i = CRYPTO_NBROUNDS_BEFORE-1; i >= 0; i--)
                skinny_round_inv(state, keyCells, i);

            /* Move result to output buffer */
            stateToCharArray(inverse, state);
        }

        /* Reinstall fork if necessary */
        if (s == INV_BOTH) {
            stateCopy(state, L);

            for (i=0; i<CRYPTO_NBROUNDS_BEFORE; i++)
                advanceKeySchedule(keyCells);
        }

        if ((s == INV_OTHER) | (s == INV_BOTH)) {
            /* Set correct keyschedule */
            for (i=0; i<CRYPTO_NBROUNDS_AFTER; i++)
                advanceKeySchedule(keyCells);

            /* Add branch constant */
            AddBranchConstant(state);

            /* From fork to C0 */
            for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++) 
                skinny_round(state, keyCells, i);

            /* Move result to output buffer */
            stateToCharArray(C_other, state);
        }
    }
    else {
        /* Advance the key schedule in order to decrypt */
        for(i = 0; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
            advanceKeySchedule(keyCells);

        /* From C0 to fork */
        for(i = CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER-1; i >= CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i--)
            skinny_round_inv(state, keyCells, i);

        /* Add branch constant */
        AddBranchConstant(state);

        /* Save fork if both blocks are needed */
        if (s == INV_BOTH) 
            stateCopy(L, state);

        //print_fork(state);

        /* Set correct keyschedule */
        for(i = 0; i < CRYPTO_NBROUNDS_AFTER; i++)
            reverseKeySchedule(keyCells);

        if ((s == INV_BOTH) | (s == INV_INVERSE)) {
            /* From fork to M */
            for(i = CRYPTO_NBROUNDS_BEFORE-1; i >= 0; i--)
                skinny_round_inv(state, keyCells, i);

            /* Move result into output buffer */
            stateToCharArray(inverse, state);

        }

        /* Reinstall fork and correct key schedule if necessary */
        if (s == INV_BOTH) {
            stateCopy(state, L);

            for (i=0; i<CRYPTO_NBROUNDS_BEFORE; i++)
                advanceKeySchedule(keyCells);
        }

        if ((s == INV_BOTH) | (s == INV_OTHER)) {
            /* From fork to C1 */
            for(i = CRYPTO_NBROUNDS_BEFORE; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++) // for i in range(nbRounds)
                skinny_round(state, keyCells, i);

            /* Move result to output buffer */
            stateToCharArray(C_other, state);
        }
    }
    
    /* Null pointer for invalid outputs */
    if (s == INV_INVERSE) 
        C_other = NULL;
    else if (s == INV_OTHER) 
        inverse = NULL;
}
///////////////////////////////////////encrypt.c///////////////////////////////////////////////////////

/**
 * The CAESAR encrypt interface
 * @param c A pointer to buffer for CT
 * @param clen Ciphertext length in Bytes
 * @param k The secret key
 * @param m A pointer to the PT
 * @param mlen Plaintext length in Bytes
 * @param ad A pointer to associated data
 * @param adlen Length of associated data in Bytes
 * @param npub A pointer to the nonce
 * @param nsec A pointer to secret message number (ignored)
 */

int crypto_aead_encrypt(
	uint8_t *c, size_t *clen,
	const uint8_t *m, size_t mlen,
	const uint8_t *ad, size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
) {
   int res = paef_encrypt(c, m, mlen, ad, adlen, npub, k);

   if (res != -1)
      *clen = mlen + CRYPTO_ABYTES;

   return res;
}

/**
 * The CAESAR decrypt interface
 * @param c A pointer to buffer for CT
 * @param clen Ciphertext length in Bytes
 * @param k The secret key
 * @param m A pointer to the PT
 * @param mlen Plaintext length in Bytes
 * @param ad A pointer to associated data
 * @param adlen Length of associated data  in Bytes
 * @param npub A pointer to the nonce
 * @param nsec A pointer to secret message number (ignored)
 */
int crypto_aead_decrypt(
	uint8_t *m, size_t *mlen,
	const uint8_t *c, size_t clen,
	const uint8_t *ad, size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
) {
   int res = paef_decrypt(m, c, clen, ad, adlen, npub, k);

   if (res != -1)
    *mlen = clen - CRYPTO_ABYTES;

   return res;
}


