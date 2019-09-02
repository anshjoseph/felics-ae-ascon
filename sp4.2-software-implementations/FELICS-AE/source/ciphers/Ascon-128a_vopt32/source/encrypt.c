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


void crypto_aead_encrypt(
    uint8_t *c, size_t *clen,
    const uint8_t *m, size_t mlen,
    const uint8_t *ad, size_t adlen,
    const uint8_t *npub,
    const uint8_t *k) {

  uint64_t rlen;
  unsigned int i;
  
  uint32_t K0_o;
  uint32_t K1_o;
  uint32_t N0_o;
  uint32_t N1_o;
  uint32_t x0_o, x1_o, x2_o, x3_o, x4_o;
  uint32_t t0_o, t1_o, t2_o;
  
  uint32_t K0_e;
  uint32_t K1_e;
  uint32_t N0_e;
  uint32_t N1_e;
  uint32_t x0_e, x1_e, x2_e, x3_e, x4_e;
  uint32_t t0_e, t1_e, t2_e;
  
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
      ad += RATE/2;
      COMPRESS_BYTE_ARRAY(ad,in_o,in_e);
      x1_e ^= in_e;
      x1_o ^= in_o;
      ad += RATE/2;
      P8_32;
      rlen -= RATE;
    }
    t1_e = t1_o = t2_e = t2_o = 0;
    for (i = 0; i < rlen; ++i, ++ad)
      if(i < 8) 
        if(i < 4)
          t1_o |= INS_BYTE32(*ad, i);
        else
          t1_e |= INS_BYTE32(*ad, (i - 4));
      else
        if(i < 12)
          t2_o |= INS_BYTE32(*ad, (i - 8));
        else
          t2_e |= INS_BYTE32(*ad, (i - 12));
    if(rlen < 8) 
      if(rlen < 4)
        t1_o |= INS_BYTE32(0x80, rlen);
      else
        t1_e |= INS_BYTE32(0x80, (rlen - 4));
    else
      if(rlen < 12)
        t2_o |= INS_BYTE32(0x80, (rlen - 8));
      else
        t2_e |= INS_BYTE32(0x80, (rlen - 12));
    COMPRESS_U32(t1_e,in_o,in_e);
    COMPRESS_U32(t1_o,t0_o,t0_e);
    in_o |= t0_o << 16;
    in_e |= t0_e << 16;
    x0_e ^= in_e;
    x0_o ^= in_o;
    COMPRESS_U32(t2_e,in_o,in_e);
    COMPRESS_U32(t2_o,t0_o,t0_e);
    in_o |= t0_o << 16;
    in_e |= t0_e << 16;
    x1_e ^= in_e;
    x1_o ^= in_o;
    P8_32;
  }
  x4_e ^= 1;

  // process plaintext
  rlen = mlen;
  while (rlen >= RATE) {
    COMPRESS_BYTE_ARRAY(m,in_o,in_e);
    x0_e ^= in_e;
    x0_o ^= in_o;
    EXPAND_U32(t1_e,x0_o>>16,x0_e>>16);
    ((uint32_t*)c)[0] = U32BIG(t1_e);
    EXPAND_U32(t1_e,x0_o,x0_e);
    ((uint32_t*)c)[1] = U32BIG(t1_e);
    m += RATE/2;
    COMPRESS_BYTE_ARRAY(m,in_o,in_e);
    x1_e ^= in_e;
    x1_o ^= in_o;
    EXPAND_U32(t1_e,x1_o>>16,x1_e>>16);
    ((uint32_t*)c)[2] = U32BIG(t1_e);
    EXPAND_U32(t1_e,x1_o,x1_e);
    ((uint32_t*)c)[3] = U32BIG(t1_e);
    m += RATE/2;
    P8_32;
    rlen -= RATE;
    c += RATE;
  }
  t1_e = t1_o = t2_e = t2_o = 0;
  for (i = 0; i < rlen; ++i, ++m) 
    if(i < 8)
      if(i < 4)
        t1_o |= INS_BYTE32(*m, i);
      else
        t1_e |= INS_BYTE32(*m, (i - 4));
    else
      if(i < 12)
        t2_o |= INS_BYTE32(*m, (i - 8));
      else
        t2_e |= INS_BYTE32(*m, (i - 12));
  if(rlen < 8) 
    if(rlen < 4)
      t1_o |= INS_BYTE32(0x80, rlen);
    else
      t1_e |= INS_BYTE32(0x80, (rlen - 4));
  else
    if(rlen < 12)
      t2_o |= INS_BYTE32(0x80, (rlen - 8));
    else
      t2_e |= INS_BYTE32(0x80, (rlen - 12));
  COMPRESS_U32(t1_e,in_o,in_e);
  COMPRESS_U32(t1_o,t0_o,t0_e);
  in_o |= t0_o << 16;
  in_e |= t0_e << 16;
  x0_e ^= in_e;
  x0_o ^= in_o;
  EXPAND_U32(t1_e,x0_o,x0_e);
  EXPAND_U32(t1_o,x0_o>>16,x0_e>>16);
  COMPRESS_U32(t2_e,in_o,in_e);
  COMPRESS_U32(t2_o,t0_o,t0_e);
  in_o |= t0_o << 16;
  in_e |= t0_e << 16;
  x1_e ^= in_e;
  x1_o ^= in_o;
  EXPAND_U32(t2_e,x1_o,x1_e);
  EXPAND_U32(t2_o,x1_o>>16,x1_e>>16);
  for (i = 0; i < rlen; ++i, ++c)
    if(i < 8)
      if(i < 4)
        *c = EXT_BYTE32(t1_o, i);
      else
        *c = EXT_BYTE32(t1_e, i - 4);
    else
      if(i < 12)
        *c = EXT_BYTE32(t2_o, i - 8);
      else
        *c = EXT_BYTE32(t2_e, i - 12);

  // finalization
  x2_e ^= K0_e;
  x2_o ^= K0_o;
  x3_e ^= K1_e;
  x3_o ^= K1_o;
  P12_32;
  x3_e ^= K0_e;
  x3_o ^= K0_o;
  x4_e ^= K1_e;
  x4_o ^= K1_o;

  // return tag
  EXPAND_U32(t1_e,x3_o>>16,x3_e>>16);
  ((uint32_t*)c)[0] = U32BIG(t1_e);
  EXPAND_U32(t1_e,x3_o,x3_e);
  ((uint32_t*)c)[1] = U32BIG(t1_e);
  EXPAND_U32(t1_e,x4_o>>16,x4_e>>16);
  ((uint32_t*)c)[2] = U32BIG(t1_e);
  EXPAND_U32(t1_e,x4_o,x4_e);
  ((uint32_t*)c)[3] = U32BIG(t1_e);
  *clen = mlen + CRYPTO_KEYBYTES;
}
