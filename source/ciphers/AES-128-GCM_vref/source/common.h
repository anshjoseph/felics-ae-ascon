#ifndef COMMON_H
#define COMMON_H

int crypto_core_aes128encrypt(
        unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
);

#define AES(out,in,k) crypto_core_aes128encrypt(out,in,k,0)

static inline void store32(unsigned char *x,unsigned long long u)
{
  int i;
  for (i = 3;i >= 0;--i) { x[i] = u; u >>= 8; }
}

static inline void store64(unsigned char *x,unsigned long long u)
{
  int i;
  for (i = 7;i >= 0;--i) { x[i] = u; u >>= 8; }
}

void addmul(unsigned char *a,
  const unsigned char *x,unsigned long long xlen,
  const unsigned char *y);

extern unsigned char zero[16];

#endif /* COMMON_H */
