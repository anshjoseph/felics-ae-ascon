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

  uint64_t rlen;
  unsigned int i;

  uint32_t K0_o;
  uint32_t K1_o;
  uint32_t N0_o;
  uint32_t N1_o;
  uint32_t x0_o, x1_o, x2_o, x3_o, x4_o;
  uint32_t t0_o, t1_o;

  uint32_t K0_e;
  uint32_t K1_e;
  uint32_t N0_e;
  uint32_t N1_e;
  uint32_t x0_e, x1_e, x2_e, x3_e, x4_e;
  uint32_t t0_e, t1_e;

  uint32_t in_o, in_e;

  COMPRESS_BYTE_ARRAY(k,K0_o,K0_e);
  COMPRESS_BYTE_ARRAY(k+8,K1_o,K1_e);
  COMPRESS_BYTE_ARRAY(npub,N0_o,N0_e);
  COMPRESS_BYTE_ARRAY(npub+8,N1_o,N1_e);


  // initialization
  t1_e = (uint32_t)((CRYPTO_KEYBYTES * 8) << 24 | (RATE * 8) << 16 | PA_ROUNDS << 8 | PB_ROUNDS << 0);
  t1_o = t1_e >> 1;
  COMPRESS_LONG(t1_e);
  COMPRESS_LONG(t1_o);
  x0_e = t1_e << 16;
  x0_o = t1_o << 16;
  x1_o = K0_o;
  x1_e = K0_e;
  x2_e = K1_e;
  x2_o = K1_o;
  x3_e = N0_e;
  x3_o = N0_o;
  x4_e = N1_e;
  x4_o = N1_o;
  P12_32;
  x3_e ^= K0_e;
  x3_o ^= K0_o;
  x4_e ^= K1_e;
  x4_o ^= K1_o;
  // process associated data
  if (adlen) {
    rlen = adlen;
    while (rlen >= RATE) {
      COMPRESS_BYTE_ARRAY(ad,in_o,in_e);
      x0_e ^= in_e;
      x0_o ^= in_o;
      P6_32;
      rlen -= RATE;
      ad += RATE;
    }
    t1_e = 0;
    t1_o = 0;
    for (i = 0; i < rlen; ++i, ++ad)
      if(i < 4)
        t1_o |= INS_BYTE32(*ad, i);
      else
        t1_e |= INS_BYTE32(*ad, (i - 4));
    if(rlen < 4)
      t1_o |= INS_BYTE32(0x80, rlen);
    else
      t1_e |= INS_BYTE32(0x80, (rlen - 4));
    COMPRESS_U32(t1_e,in_o,in_e);
    COMPRESS_U32(t1_o,t0_o,t0_e);
    in_o |= t0_o << 16;
    in_e |= t0_e << 16;
    x0_e ^= in_e;
    x0_o ^= in_o;
    P6_32;
  }
  x4_e ^= 1;

  // process plaintext
  rlen = clen - CRYPTO_KEYBYTES;
  while (rlen >= RATE) {
    EXPAND_U32(t1_e,x0_o,x0_e);
    EXPAND_U32(t1_o,x0_o>>16,x0_e>>16);
    ((uint32_t*)m)[0] = U32BIG(t1_o) ^ ((uint32_t*)c)[0];
    ((uint32_t*)m)[1] = U32BIG(t1_e) ^ ((uint32_t*)c)[1];
    COMPRESS_BYTE_ARRAY(c,x0_o,x0_e);
    P6_32;
    rlen -= RATE;
    m += RATE;
    c += RATE;
  }
  EXPAND_U32(t1_e,x0_o,x0_e);
  EXPAND_U32(t1_o, x0_o >> 16, x0_e >> 16);
  for (i = 0; i < rlen; ++i, ++m, ++c) {
    if (i < 4) {
      *m = EXT_BYTE32(t1_o, i) ^ *c;
      t1_o &= ~INS_BYTE32(0xff, i);
      t1_o |= INS_BYTE32(*c, i);
    } else {
      *m = EXT_BYTE32(t1_e, i-4) ^ *c;
      t1_e &= ~INS_BYTE32(0xff, i-4);
      t1_e |= INS_BYTE32(*c, i-4);
    }
  }
  if (rlen < 4)
    t1_o ^= INS_BYTE32(0x80, rlen);
  else
    t1_e ^= INS_BYTE32(0x80, rlen-4);

  COMPRESS_U32(t1_e,x0_o,x0_e);
  COMPRESS_U32(t1_o,t0_o,t0_e);
  x0_o |= t0_o << 16;
  x0_e |= t0_e << 16;

  // finalization
  x1_e ^= K0_e;
  x1_o ^= K0_o;
  x2_e ^= K1_e;
  x2_o ^= K1_o;
  P12_32;
  x3_e ^= K0_e;
  x3_o ^= K0_o;
  x4_e ^= K1_e;
  x4_o ^= K1_o;

  // return -1 if verification fails
  int ret_val = 0;
  EXPAND_U32(t1_e, x3_o, x3_e);
  EXPAND_U32(t1_o, x3_o >> 16, x3_e >> 16);
  if (((uint32_t*) c)[0] != U32BIG(t1_o))
    ret_val--;
  else
    ret_val++;
  if (((uint32_t*) c)[1] != U32BIG(t1_e))
    ret_val--;
  else
    ret_val++;
  EXPAND_U32(t1_e, x4_o, x4_e);
  EXPAND_U32(t1_o, x4_o >> 16, x4_e >> 16);
  if (((uint32_t*) c)[2] != U32BIG(t1_o))
    ret_val--;
  else
    ret_val++;
  if (((uint32_t*) c)[3] != U32BIG(t1_e))
    ret_val--;
  else
    ret_val++;

  if (ret_val != 4)
    return -1;

  // return plaintext
  *mlen = clen - CRYPTO_KEYBYTES;
  return 0;
}
