/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"


#define ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))

static void load64(uint64_t* x, uint8_t* S) {
  int i;
  *x = 0;
  for (i = 0; i < 8; ++i)
    *x |= ((uint64_t) S[i]) << (56 - i * 8);
}

static void store64(uint8_t* S, uint64_t x) {
  int i;
  for (i = 0; i < 8; ++i)
    S[i] = (uint8_t) (x >> (56 - i * 8));
}

void permutation(uint8_t* S, int start, int rounds) {
  int i;
  uint64_t x0, x1, x2, x3, x4;
  uint64_t t0, t1, t2, t3, t4;
  load64(&x0, S + 0);
  load64(&x1, S + 8);
  load64(&x2, S + 16);
  load64(&x3, S + 24);
  load64(&x4, S + 32);
  for (i = start; i < start + rounds; ++i) {
    // addition of round constant
    x2 ^= ((0xfull - i) << 4) | i;
    // substitution layer
    x0 ^= x4;    x4 ^= x3;    x2 ^= x1;
    t0  = x0;    t1  = x1;    t2  = x2;    t3  = x3;    t4  = x4;
    t0 =~ t0;    t1 =~ t1;    t2 =~ t2;    t3 =~ t3;    t4 =~ t4;
    t0 &= x1;    t1 &= x2;    t2 &= x3;    t3 &= x4;    t4 &= x0;
    x0 ^= t1;    x1 ^= t2;    x2 ^= t3;    x3 ^= t4;    x4 ^= t0;
    x1 ^= x0;    x0 ^= x4;    x3 ^= x2;    x2 =~ x2;
    // linear diffusion layer
    x0 ^= ROTR(x0, 19) ^ ROTR(x0, 28);
    x1 ^= ROTR(x1, 61) ^ ROTR(x1, 39);
    x2 ^= ROTR(x2,  1) ^ ROTR(x2,  6);
    x3 ^= ROTR(x3, 10) ^ ROTR(x3, 17);
    x4 ^= ROTR(x4,  7) ^ ROTR(x4, 41);
  }
  store64(S + 0, x0);
  store64(S + 8, x1);
  store64(S + 16, x2);
  store64(S + 24, x3);
  store64(S + 32, x4);
}

static void crypto_aead_encrypt(
    uint8_t *c, size_t *clen,
    const uint8_t *m, size_t mlen,
    const uint8_t *ad, size_t adlen,
    const uint8_t *npub,
    const uint8_t *k) {

  size_t klen = CRYPTO_KEYBYTES;
  //int nlen = CRYPTO_NPUBBYTES;
  size_t size = 320 / 8;
  size_t rate = 128 / 8;
  int a = 12;
  int b = 8;
  size_t s = adlen / rate + 1;
  size_t t = mlen / rate + 1;
  size_t l = mlen % rate;

  uint8_t S[size];
  uint8_t A[s * rate];
  uint8_t M[t * rate];
  size_t i, j;

  // pad associated data
  for (i = 0; i < adlen; ++i)
    A[i] = ad[i];
  A[adlen] = 0x80;
  for (i = adlen + 1; i < s * rate; ++i)
    A[i] = 0;
  // pad plaintext
  for (i = 0; i < mlen; ++i)
    M[i] = m[i];
  M[mlen] = 0x80;
  for (i = mlen + 1; i < t * rate; ++i)
    M[i] = 0;

  // initialization
  S[0] = klen * 8;
  S[1] = rate * 8;
  S[2] = a;
  S[3] = b;
  for (i = 4; i < size - 2 * klen; ++i)
    S[i] = 0;
  for (i = 0; i < klen; ++i)
    S[size - 2 * klen + i] = k[i];
  for (i = 0; i < klen; ++i)
    S[size - klen + i] = npub[i];
  permutation(S, 12 - a, a);
  for (i = 0; i < klen; ++i)
    S[size - klen + i] ^= k[i];

  // process associated data
  if (adlen != 0) {
    for (i = 0; i < s; ++i) {
      for (j = 0; j < rate; ++j)
        S[j] ^= A[i * rate + j];
      permutation(S, 12 - b, b);
    }
  }
  S[size - 1] ^= 1;

  // process plaintext
  for (i = 0; i < t - 1; ++i) {
    for (j = 0; j < rate; ++j) {
      S[j] ^= M[i * rate + j];
      c[i * rate + j] = S[j];
    }
    permutation(S, 12 - b, b);
  }
  for (j = 0; j < rate; ++j)
    S[j] ^= M[(t - 1) * rate + j];
  for (j = 0; j < l; ++j)
    c[(t - 1) * rate + j] = S[j];

  // finalization
  for (i = 0; i < klen; ++i)
    S[rate + i] ^= k[i];
  permutation(S, 12 - a, a);
  for (i = 0; i < klen; ++i)
    S[size - klen + i] ^= k[i];

  // return tag
  for (i = 0; i < klen; ++i)
    c[mlen + i] = S[size - klen + i];
  *clen = mlen + klen;
}

void Encrypt(uint8_t *block, size_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t  adlen, uint8_t *c)
{
    size_t clen;
    crypto_aead_encrypt(c, &clen, block, mlen, ad, adlen, npub, key);
}
