#include <stdint.h>

#include "utils.h"


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
