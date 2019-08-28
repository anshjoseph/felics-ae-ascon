#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "felics/cipher.h"
#include "utils.h"


/*
  This is the optimized implementation of ACORN-128.

  In the implementation, we store the 293-bit register into 7 64-bit registers:
  293-bit register R:  r292 r291 r290 r289 r288 r287 r286 r285 ...... r5 r4 r3 r2 r1 r0

  state[0]:  r60  r59  r58  r57  ...... r2   r1   r0     (61 bits) (lsb: r0)
  state[1]:  r106 r105 r104 r103 ...... r63  r62  r61    (46 bits) (lsb: r61)
  state[2]:  r153 r152 r151 r150 ...... r109 r108 r107   (47 bits) (lsb: r107)
  state[3]:  r192 r191 r190 r189 ...... r156 r155 r154   (39 bits) (lsb: r154)
  state[4]:  r229 r228 r227 r226 ...... r195 r194 r193   (37 bits) (lsb: r193)
  state[5]:  r288 r287 r286 r285 ...... r232 r231 r230   (59 bits) (lsb: r230)
  state[6]:  r292 r291 r290 r289                         (4  bits) (lsb: r289)
*/


// encrypt a message
void crypto_aead_encrypt(
	uint8_t *c,size_t *clen,
	const uint8_t *m,size_t mlen,
	const uint8_t *ad,size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
	)
{
    size_t i;
    uint8_t mac[16];
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

    // if adlen is not a multiple of 4, we process the remaining bytes
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
    for (i = 0; i < mlen/4; i=i+1)
    {
        encrypt_32bits_fast(state, ((uint32_t*)m)[i], &(((uint32_t*)c)[i]), ca);  //&c[i], &ksword, ca, cb);
    }

    //if mlen is not a multiple of 32 bits, we process the remaining bytes.
    for (i = mlen & (uint64_t)0xfffffffffffffffc; i < mlen; i++)
    {
        plaintextword = m[i];
        encrypt_8bits(state, plaintextword, &ciphertextword, ca, cb);
        c[i] = ciphertextword;
    }

    //256 bits padding after the plaintext
    acorn128_padding_256(state,cb);

    //finalization stage, we assume that the tag length is a multiple of bytes
    acorn128_tag_generation_32bits_version(mac, state);
    *clen = mlen + 16;
    memcpy(c+mlen, mac, 16);
}
