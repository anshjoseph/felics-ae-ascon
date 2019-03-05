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


void permutation(uint8_t* S, int start, int rounds);

static int crypto_aead_decrypt(
    uint8_t *m, size_t *mlen,
    const uint8_t *c, size_t clen,
    const uint8_t *ad, size_t adlen,
    const uint8_t *npub,
    const uint8_t *k) {

  *mlen = 0;
  if (clen < CRYPTO_KEYBYTES)
    return -1;

  size_t klen = CRYPTO_KEYBYTES;
  //int nlen = CRYPTO_NPUBBYTES;
  size_t size = 320 / 8;
  size_t rate = 64 / 8;
  int a = 12;
  int b = 6;
  size_t s = adlen / rate + 1;
  size_t t = (clen - klen) / rate + 1;
  size_t l = (clen - klen) % rate;

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
    S[rate + klen + i] ^= k[i];

  // process associated data
  if (adlen) {
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
      M[i * rate + j] = S[j] ^ c[i * rate + j];
      S[j] = c[i * rate + j];
    }
    permutation(S, 12 - b, b);
  }
  for (j = 0; j < l; ++j)
    M[(t - 1) * rate + j] = S[j] ^ c[(t - 1) * rate + j];
  for (j = 0; j < l; ++j)
    S[j] = c[(t - 1) * rate + j];
  S[l] ^= 0x80;

  // finalization
  for (i = 0; i < klen; ++i)
    S[rate + i] ^= k[i];
  permutation(S, 12 - a, a);
  for (i = 0; i < klen; ++i)
    S[rate + klen + i] ^= k[i];

  // return -1 if verification fails
  for (i = 0; i < klen; ++i)
    if (c[clen - klen + i] != S[rate + klen + i])
      return -1;

  // return plaintext
  *mlen = clen - klen;
  for (i = 0; i < *mlen; ++i)
    m[i] = M[i];

  return 0;
}

int Decrypt(uint8_t *block, size_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t  adlen, uint8_t *c)
{
    return crypto_aead_decrypt(block, &mlen, c, mlen+CRYPTO_ABYTES, ad, adlen, npub, key);
}
