#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>

int crypto_core_aes128encrypt(
        uint8_t *out,
  const uint8_t *in,
  const uint8_t *k,
  const uint8_t *c
);

#define AES(out,in,k) crypto_core_aes128encrypt(out,in,k,0)

static inline void store32(uint8_t *x,size_t u)
{
  int i;
  for (i = 3;i >= 0;--i) { x[i] = u; u >>= 8; }
}

static inline void store64(uint8_t *x,size_t u)
{
  int i;
  for (i = 7;i >= 0;--i) { x[i] = u; u >>= 8; }
}

void addmul(uint8_t *a,
  const uint8_t *x,size_t xlen,
  const uint8_t *y);

extern uint8_t zero[16];

#endif /* COMMON_H */
