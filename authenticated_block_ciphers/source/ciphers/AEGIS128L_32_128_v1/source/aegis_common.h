#ifndef AEGIS_COMMON_H
#define AEGIS_COMMON_H

#include "constants.h"
#include "aegis_utils.h"


// The initialization state of AEGIS
/*The input to initialization is the 128-bit key; 128-bit IV;*/
static inline void aegis128L_initialization(const uint8_t *key, const uint8_t *iv, uint8_t *state)
{
       unsigned int i;
       uint8_t tmp[16];
       uint8_t constant[32] = {0x0,0x1,0x01,0x02,0x03,0x05,0x08,0x0d,0x15,0x22,0x37,0x59,0x90,0xe9,0x79,0x62,0xdb,0x3d,0x18,0x55,0x6d,0xc2,0x2f,0xf1,0x20,0x11,0x31,0x42,0x73,0xb5,0x28,0xdd};

       XOR128(state,  key,  iv);
       memcpy(state+16, constant+16, 16);
       memcpy(state+32, constant,    16);
       memcpy(state+48, constant+16, 16);
       XOR128(state+64, key, iv);
       XOR128(state+80, key, constant);
       XOR128(state+96, key, constant+16);
       XOR128(state+112,key, constant);

       for (i = 0; i < 10; i++)  {
             //state update function;
             memcpy(tmp, state+112, 16);

             AESROUND(state+112,state+96, state+112);
             AESROUND(state+96, state+80, state+96);
             AESROUND(state+80, state+64, state+80);
             AESROUND(state+64, state+48, state+64);
             AESROUND(state+48, state+32, state+48);
             AESROUND(state+32, state+16, state+32);
             AESROUND(state+16, state+0,  state+16);
             AESROUND(state+0,  tmp,      state+0);

             //message is used to update the state.
             XOR128(state, state, iv);
             XOR128(state+64, state+64, key);
       }
}

//the finalization state of AEGIS
static inline void aegis128L_tag_generation(size_t msglen, size_t adlen, uint8_t maclen, uint8_t *mac, uint8_t *state)
{
        unsigned int i;

        uint8_t tmp[16];
        uint8_t msgtmp[16];

        msgtmp_init(msgtmp, msglen, adlen);

        XOR128(msgtmp, msgtmp, state+32);

        for (i = 0; i < 7; i++) {
            //state update function
            memcpy(tmp, state+112, 16);
            AESROUND(state+112,state+96, state+112);
            AESROUND(state+96, state+80, state+96);
            AESROUND(state+80, state+64, state+80);
            AESROUND(state+64, state+48, state+64);
            AESROUND(state+48, state+32, state+48);
            AESROUND(state+32, state+16, state+32);
            AESROUND(state+16, state+0,  state+16);
            AESROUND(state+0,  tmp,      state+0);

            //message is used to update the state.
            XOR128(state,    state,    msgtmp);
            XOR128(state+64, state+64, msgtmp);
        }

        XOR128(state+96, state+96, state+80);
        XOR128(state+96, state+96, state+64);
        XOR128(state+96, state+96, state+48);
        XOR128(state+96, state+96, state+32);
        XOR128(state+96, state+96, state+16);
        XOR128(state+96, state+96, state+0);

        //in this program, the mac length is assumed to be multiple of bytes
        memcpy(mac,state+96,maclen);
}

// one step of encryption
static inline void aegis128L_enc_aut_step(const uint8_t *plaintextblk,
       uint8_t *ciphertextblk, uint8_t *state)
{
    uint8_t tmp[16];

    AND128(ciphertextblk, state+32, state+48);
    XOR128(ciphertextblk, ciphertextblk, state+16);
    XOR128(ciphertextblk, ciphertextblk, state+96);
    XOR128(ciphertextblk, ciphertextblk, plaintextblk);

    AND128(ciphertextblk+16, state+96, state+112);
    XOR128(ciphertextblk+16, ciphertextblk+16, state+32);
    XOR128(ciphertextblk+16, ciphertextblk+16, state+80);
    XOR128(ciphertextblk+16, ciphertextblk+16, plaintextblk+16);

    memcpy(tmp, state+112, 16);
    AESROUND(state+112,state+96, state+112);
    AESROUND(state+96, state+80, state+96);
    AESROUND(state+80, state+64, state+80);
    AESROUND(state+64, state+48, state+64);
    AESROUND(state+48, state+32, state+48);
    AESROUND(state+32, state+16, state+32);
    AESROUND(state+16, state+0,  state+16);
    AESROUND(state+0,  tmp,      state+0);

    //message is used to update the state.
    XOR128(state, state, plaintextblk);
    XOR128(state+64, state+64, plaintextblk+16);
}


#endif /* AEGIS_COMMON_H */
