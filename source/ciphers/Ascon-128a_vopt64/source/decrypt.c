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

#include "felics/cipher.h"
#include "api.h"
#include "utils.h"


int crypto_aead_decrypt(
    uint8_t *m, size_t *mlen,
    const uint8_t *c, size_t clen,
    const uint8_t *ad, size_t adlen,
    const uint8_t *npub,
    const uint8_t *k) {

  *mlen = 0;
  if (clen < CRYPTO_KEYBYTES)
    return -1;

  uint64_t K0 = U64BIG(((uint64_t*)k)[0]);
  uint64_t K1 = U64BIG(((uint64_t*)k)[1]);
  uint64_t N0 = U64BIG(((uint64_t*)npub)[0]);
  uint64_t N1 = U64BIG(((uint64_t*)npub)[1]);
  uint64_t x0, x1, x2, x3, x4;
  uint64_t t0, t1, t2, t3, t4;
  uint64_t rlen;
  size_t i;

  // initialization
  x0 = (uint64_t)((CRYPTO_KEYBYTES * 8) << 24 | (RATE * 8) << 16 | PA_ROUNDS << 8 | PB_ROUNDS << 0) << 32;
  x1 = K0;
  x2 = K1;
  x3 = N0;
  x4 = N1;
  P12;
  x3 ^= K0;
  x4 ^= K1;

  // process associated data
  if (adlen) {
    rlen = adlen;
    while (rlen >= RATE) {
      x0 ^= U64BIG(*(uint64_t*)ad);
      x1 ^= U64BIG(*(uint64_t*)(ad + 8));
      P8;
      rlen -= RATE;
      ad += RATE;
    }
    for (i = 0; i < rlen; ++i, ++ad)
      if (i < 8)
        x0 ^= INS_BYTE(*ad, i);
      else
        x1 ^= INS_BYTE(*ad, i);
    if (rlen < 8)
      x0 ^= INS_BYTE(0x80, rlen);
    else
      x1 ^= INS_BYTE(0x80, rlen);
    P8;
  }
  x4 ^= 1;

  // process plaintext
  rlen = clen - CRYPTO_KEYBYTES;
  while (rlen >= RATE) {
    *(uint64_t*)m = U64BIG(x0) ^ *(uint64_t*)c;
    *(uint64_t*)(m + 8) = U64BIG(x1) ^ *(uint64_t*)(c + 8);
    x0 = U64BIG(*((uint64_t*)c));
    x1 = U64BIG(*((uint64_t*)(c + 8)));
    P8;
    rlen -= RATE;
    m += RATE;
    c += RATE;
  }
  for (i = 0; i < rlen; ++i, ++m, ++c) {
    if (i < 8) {
      *m = EXT_BYTE(x0, i) ^ *c;
      x0 &= ~INS_BYTE(0xff, i);
      x0 |= INS_BYTE(*c, i);
    } else {
      *m = EXT_BYTE(x1, i) ^ *c;
      x1 &= ~INS_BYTE(0xff, i);
      x1 |= INS_BYTE(*c, i);
    }
  }
  if (rlen < 8)
    x0 ^= INS_BYTE(0x80, rlen);
  else
    x1 ^= INS_BYTE(0x80, rlen);

  // finalization
  x2 ^= K0;
  x3 ^= K1;
  P12;
  x3 ^= K0;
  x4 ^= K1;

  // return -1 if verification fails
  if (((uint64_t*)c)[0] != U64BIG(x3) ||
      ((uint64_t*)c)[1] != U64BIG(x4))
    return -1;

  // return plaintext
  *mlen = clen - CRYPTO_KEYBYTES;
  return 0;
}
