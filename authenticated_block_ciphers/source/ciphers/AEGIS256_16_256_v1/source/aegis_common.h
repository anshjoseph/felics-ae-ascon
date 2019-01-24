#ifndef AEGIS_COMMON_H
#define AEGIS_COMMON_H

#include "constants.h"

/* NB: this function used to make heavy use of uint8_t* => uint32_t*
 * casts, which broke due to some SSE-related gcc optimization. The
 * problem could be workd around by
 *
 * * adding __attribute__ ((target("no-sse"))) to this function
 * * compiling with -fsanitize=alignment
 *
 * Following advice from [1], I figure memcpy(3) is the way to go.
 *
 * [1]: http://pzemtsov.github.io/2016/11/06/bug-story-alignment-on-x86.html
 */
static inline void AESROUND(uint8_t *out, uint8_t *in, uint8_t *rk)
{
    RAM_DATA_DOUBLE_WORD out32[4];

    for (size_t i=0; i<4; i++)
    {
        memcpy(out32+i, rk+4*i, 4);

        for (size_t j=0; j<4; j++)
        {
            size_t in_index = 4*i+5*j & 0xf;
            size_t TE_index = 4*in[in_index];

            RAM_DATA_DOUBLE_WORD TEj_32;
            ROM_memcpy(&TEj_32, &TE[j][TE_index], 4);

            out32[i] ^= TEj_32;
        }
    }

    memcpy(out, out32, sizeof(out32));
}

#define XOR128(x,y,z) {                                                                             \
    ((uint64_t*)(x))[0] = ((uint64_t*)(y))[0] ^ ((uint64_t*)(z))[0];  \
    ((uint64_t*)(x))[1] = ((uint64_t*)(y))[1] ^ ((uint64_t*)(z))[1];  \
}

#define AND128(x,y,z) {                                                                             \
    ((uint64_t*)(x))[0] = ((uint64_t*)(y))[0] & ((uint64_t*)(z))[0];  \
    ((uint64_t*)(x))[1] = ((uint64_t*)(y))[1] & ((uint64_t*)(z))[1];  \
}

// The initialization state of AEGIS
static inline void aegis256_initialization(const uint8_t *key, const uint8_t *iv, uint8_t *state)
{
       unsigned int i;
       uint8_t constant[32] = {0x0,0x1,0x01,0x02,0x03,0x05,0x08,0x0d,0x15,0x22,0x37,0x59,0x90,0xe9,0x79,0x62,0xdb,0x3d,0x18,0x55,0x6d,0xc2,0x2f,0xf1,0x20,0x11,0x31,0x42,0x73,0xb5,0x28,0xdd};
       RAM_DATA_BYTE tmp[16], temp[64];

  	    XOR128(state,    key,    iv);
  	    XOR128(state+16, key+16, iv+16);

        memcpy(state+32, constant+16,  16);
        memcpy(state+48, constant,     16);
        XOR128(state+64, key,    constant);
        XOR128(state+80, key+16, constant+16);

        memcpy(temp,     key,  32);
        XOR128(temp+32,  key,  iv);
        XOR128(temp+48,  key+16, iv+16);

        for (i = 0; i < 16; i++)
        {
             //state update function
             memcpy(tmp, state+80, 16);
             AESROUND(state+80, state+64, state+80);
             AESROUND(state+64, state+48, state+64);
             AESROUND(state+48, state+32, state+48);
             AESROUND(state+32, state+16, state+32);
             AESROUND(state+16, state+0,  state+16);
             AESROUND(state+0,  tmp,      state+0);

             XOR128(state, state, temp+16*(i&3));
        }
}

//the finalization state of AEGIS
static inline void aegis256_tag_generation(uint64_t msglen, uint64_t adlen, uint8_t maclen, uint8_t *mac, uint8_t *state)
{
        int i;

        RAM_DATA_BYTE tmp[16];
        RAM_DATA_BYTE msgtmp[16];

        ((uint64_t*)msgtmp)[0] = adlen << 3;
        ((uint64_t*)msgtmp)[1] = msglen << 3;

        XOR128(msgtmp, msgtmp, state+48);

        for (i = 0; i < 7; i++) {
             //state update function
             memcpy(tmp, state+80, 16);

             AESROUND(state+80, state+64, state+80);
             AESROUND(state+64, state+48, state+64);
             AESROUND(state+48, state+32, state+48);
             AESROUND(state+32, state+16, state+32);
             AESROUND(state+16, state+0,  state+16);
             AESROUND(state+0,  tmp,      state+0);

             //xor "msg" with state[0]
             XOR128(state, state, msgtmp);
        }

        XOR128(state+80, state+80, state+64);
        XOR128(state+80, state+80, state+48);
        XOR128(state+80, state+80, state+32);
        XOR128(state+80, state+80, state+16);
        XOR128(state+80, state+80, state+0);

        //in this program, the mac length is assumed to be multiple of bytes
        memcpy(mac, state+80, maclen);
}

// one step of encryption
 static inline void aegis256_enc_aut_step(const uint8_t *plaintextblk,
       uint8_t *ciphertextblk, uint8_t *state)
{
    RAM_DATA_BYTE tmp[16];

        AND128(ciphertextblk, state+32, state+48);
        XOR128(ciphertextblk, ciphertextblk, state+16);
        XOR128(ciphertextblk, ciphertextblk, state+64);
        XOR128(ciphertextblk, ciphertextblk, state+80);
        XOR128(ciphertextblk, ciphertextblk, plaintextblk);

        //state update function
        memcpy(tmp, state+80, 16);

        AESROUND(state+80, state+64, state+80);
        AESROUND(state+64, state+48, state+64);
        AESROUND(state+48, state+32, state+48);
        AESROUND(state+32, state+16, state+32);
        AESROUND(state+16, state+0,  state+16);
        AESROUND(state+0,  tmp,      state+0);

        //message is used to update the state.
        XOR128(state, state, plaintextblk);
}


#endif /* AEGIS_COMMON_H */
