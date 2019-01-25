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

#include "cipher.h"
#include "constants.h"

#include <string.h>
#include <stdlib.h>


/* -------------------------- */

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t i64;




void load64(u64* x, u8* S) {
  int32_t i;
  *x = 0;
  for (i = 0; i < 8; ++i)
    *x |= ((u64) S[i]) << (56 - i * 8);
}

void store64(u8* S, u64 x) {
  int32_t i;
  for (i = 0; i < 8; ++i)
    S[i] = (u8) (x >> (56 - i * 8));
}

void load32(u32* x, u8* S) {
  int32_t i;
  *x = 0;
  for (i = 0; i < 4; ++i)
    *x |= ((u32) S[i]) << (24 - i * 8);
}

void store32(u8* S, u32 x) {
  int32_t i;
  for (i = 0; i < 4; ++i)
    S[i] = (u8) (x >> (24 - i * 8));
}

/*uint32_t rot64r(uint64_t x, uint32_t dec){
	
}*/

void rot19(uint8_t *S){
	u64 x0;
	u32 y0;
    u32 y1;
    u32 temp;
    u64 x0b;
    
    //store64(S + 0, x0);
	load32(&y0, S + 0);
	load32(&y1, S + 4);
	
	temp = y1<<13;
	y1 = (y1>>19) | (y0<<13);
	y0 = (y0>>19) | temp;
	
	x0b = (u64) y0;
	x0 = (u64)(x0b<<32) | (u64)(y1);
	
	store64(S + 0, x0);
}

void rot28(uint8_t *S){
	u64 x0;
	u32 y0;
    u32 y1;
    u32 temp;
    u64 x0b;
    
    //store64(S + 0, x0);
	load32(&y0, S + 0);
	load32(&y1, S + 4);
	
	temp = y1<<4;
	y1 = (y1>>28) | (y0<<4);
	y0 = (y0>>28) | temp;
	
	x0b = (u64) y0;
	x0 = (u64)(x0b<<32) | (u64)(y1);
	
	store64(S + 0, x0);
}

void rot61(uint8_t *S){
	u64 x0;
	u32 y0;
    u32 y1;
    u32 temp;
    u64 x0b;
    
    //store64(S + 0, x0);
	load32(&y0, S + 0);
	load32(&y1, S + 4);
	
	temp = y0;
	y0 = y1;
	y1 = temp;
	
	temp = y1<<3;
	y1 = (y1>>29) | (y0<<3);
	y0 = (y0>>29) | temp;
	
	x0b = (u64) y0;
	x0 = (u64)(x0b<<32) | (u64)(y1);
	
	store64(S + 0, x0);
}

void rot39(uint8_t *S){
	u64 x0;
	u32 y0;
    u32 y1;
    u32 temp;
    u64 x0b;
    
    temp = y0;
	y0 = y1;
	y1 = temp;
    
    //store64(S + 0, x0);
	load32(&y0, S + 0);
	load32(&y1, S + 4);
	
	temp = y1<<25;
	y1 = (y1>>7) | (y0<<25);
	y0 = (y0>>7) | temp;
	
	x0b = (u64) y0;
	x0 = (u64)(x0b<<32) | (u64)(y1);
	
	store64(S + 0, x0);
}

void rot1(uint8_t *S){
	u64 x0;
	u32 y0;
    u32 y1;
    u32 temp;
    u64 x0b;
    
    //store64(S + 0, x0);
	load32(&y0, S + 0);
	load32(&y1, S + 4);
	
	temp = y1<<31;
	y1 = (y1>>1) | (y0<<31);
	y0 = (y0>>1) | temp;
	
	x0b = (u64) y0;
	x0 = (u64)(x0b<<32) | (u64)(y1);
	
	store64(S + 0, x0);
}

void rot6(uint8_t *S){
	u64 x0;
	u32 y0;
    u32 y1;
    u32 temp;
    u64 x0b;
    
    //store64(S + 0, x0);
	load32(&y0, S + 0);
	load32(&y1, S + 4);
	
	temp = y1<<26;
	y1 = (y1>>6) | (y0<<26);
	y0 = (y0>>6) | temp;
	
	x0b = (u64) y0;
	x0 = (u64)(x0b<<32) | (u64)(y1);
	
	store64(S + 0, x0);
}

void rot10(uint8_t *S){
	u64 x0;
	u32 y0;
    u32 y1;
    u32 temp;
    u64 x0b;
    
    //store64(S + 0, x0);
	load32(&y0, S + 0);
	load32(&y1, S + 4);
	
	temp = y1<<22;
	y1 = (y1>>10) | (y0<<22);
	y0 = (y0>>10) | temp;
	
	x0b = (u64) y0;
	x0 = (u64)(x0b<<32) | (u64)(y1);
	
	store64(S + 0, x0);
}

void rot17(uint8_t *S){
	u64 x0;
	u32 y0;
    u32 y1;
    u32 temp;
    u64 x0b;
    
    //store64(S + 0, x0);
	load32(&y0, S + 0);
	load32(&y1, S + 4);
	
	temp = y1<<15;
	y1 = (y1>>17) | (y0<<15);
	y0 = (y0>>17) | temp;
	
	x0b = (u64) y0;
	x0 = (u64)(x0b<<32) | (u64)(y1);
	
	store64(S + 0, x0);
}

void rot7(uint8_t *S){
	u64 x0;
	u32 y0;
    u32 y1;
    u32 temp;
    u64 x0b;
    
    //store64(S + 0, x0);
	load32(&y0, S + 0);
	load32(&y1, S + 4);
	
	temp = y1<<25;
	y1 = (y1>>7) | (y0<<25);
	y0 = (y0>>7) | temp;
	
	x0b = (u64) y0;
	x0 = (u64)(x0b<<32) | (u64)(y1);
	
	store64(S + 0, x0);
}

void rot41(uint8_t *S){
	u64 x0;
	u32 y0;
    u32 y1;
    u32 temp;
    u64 x0b;
    
    //store64(S + 0, x0);
	load32(&y0, S + 0);
	load32(&y1, S + 4);
	
	temp = y0;
	y0 = y1;
	y1 = temp;
	
	temp = y1<<23;
	y1 = (y1>>9) | (y0<<23);
	y0 = (y0>>9) | temp;
	
	x0b = (u64) y0;
	x0 = (u64)(x0b<<32) | (u64)(y1);
	
	store64(S + 0, x0);
}


void permutation(u8* S, int32_t start, int32_t rounds) {
  int32_t i;
  u64 x0, x1, x2, x3, x4;
  u64 t0, t1, t2, t3, t4;
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
    // ------------------- X0 --------------------------------//
  	uint8_t Sb0[8];
  	uint8_t Sb1[8];
  	store64(Sb0 , x0);
  	store64(Sb1 , x0);
  	rot19(Sb0);
  	rot28(Sb1);
  	uint64_t xtemp0;
	load64(&xtemp0, Sb0 );
	
	x0 ^= xtemp0;

	uint64_t xtemp1;
	load64(&xtemp1, Sb1 );
	
	x0 ^= xtemp1;
	
	
	// ------------------- X1 --------------------------------//
	//x1 ^= ROTR(x1, 61) ^ ROTR(x1, 39);
  	store64(Sb0 , x1);
  	store64(Sb1 , x1);
  	rot61(Sb0);
  	rot39(Sb1);
	load64(&xtemp0, Sb0 );
	
	x1 ^= xtemp0;

	load64(&xtemp1, Sb1 );
	
	x1 ^= xtemp1;
	
	
	// ------------------- X2 --------------------------------//
	//x2 ^= ROTR(x2,  1) ^ ROTR(x2,  6);
  	store64(Sb0 , x2);
  	store64(Sb1 , x2);
  	rot1(Sb0);
  	rot6(Sb1);
	load64(&xtemp0, Sb0 );
	
	x2 ^= xtemp0;

	load64(&xtemp1, Sb1 );
	
	x2 ^= xtemp1;
	
	
	// ------------------- X3 --------------------------------//
	//x3 ^= ROTR(x3, 10) ^ ROTR(x3, 17);
  	store64(Sb0 , x3);
  	store64(Sb1 , x3);
  	rot10(Sb0);
  	rot17(Sb1);
	load64(&xtemp0, Sb0 );
	
	x3 ^= xtemp0;

	load64(&xtemp1, Sb1 );
	
	x3 ^= xtemp1;
	
	
	// ------------------- X4 --------------------------------//
	//x4 ^= ROTR(x4,  7) ^ ROTR(x4, 41);
  	store64(Sb0 , x4);
  	store64(Sb1 , x4);
  	rot7(Sb0);
  	rot41(Sb1);
	load64(&xtemp0, Sb0 );
	
	x4 ^= xtemp0;

	load64(&xtemp1, Sb1 );
	
	x4 ^= xtemp1;
    
  }
  store64(S + 0, x0);
  store64(S + 8, x1);
  store64(S + 16, x2);
  store64(S + 24, x3);
  store64(S + 32, x4);
}


/*------------------------------*/

int32_t crypto_aead_encrypt(
	uint8_t *c, int32_t *clen,
	const uint8_t *m, int32_t mlen,
	const uint8_t *ad, int32_t adlen,
	const uint8_t *nsec,
	const uint8_t *npub,
	uint8_t *k
	)
{
  int32_t klen = KEY_SIZE;
  //int nlen = CRYPTO_NPUBBYTES;
  int32_t size = 320 / 8;
  int32_t rate = 128 / 8;
  int32_t a = 12;
  int32_t b = 8;
  i64 s = adlen / rate + 1;
  i64 t = mlen / rate + 1;
  i64 l = mlen % rate;

  u8 S[size];
  u8 A[s * rate];
  u8 M[t * rate];
  i64 i, j;

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

  return 0;
}


/*--------------------------------*/

void Encrypt(uint8_t *block, int32_t  mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, int32_t  adlen, uint8_t *c, uint8_t *roundKeys)
{

	static uint8_t *nsec;
	nsec = malloc(CRYPTO_NSECBYTES);
	
	//length of inputs and param
	int32_t clen = mlen + CRYPTO_ABYTES;
	
	uint8_t *AD;
    AD = (uint8_t *) malloc(adlen * sizeof(uint8_t) );
    memcpy(AD, ad, adlen);
	
	
	if(adlen !=16){
	crypto_aead_encrypt(
	c, &clen,
	block, mlen,
	AD, adlen,
	nsec,
	npub,
	key
	);}
	else if(adlen ==16){
	crypto_aead_encrypt(
	c, &clen,
	block, mlen,
	AD, adlen,
	nsec,
	npub,
	key
	);
	}
	
	
}



