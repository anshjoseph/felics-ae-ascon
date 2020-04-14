#include <stddef.h>
#include <stdint.h>

#include "common.h"

static int crypto_verify_16(const uint8_t *x,const uint8_t *y)
{
  unsigned int differentbits = 0;
#define F(i) differentbits |= x[i] ^ y[i];
  F(0)
  F(1)
  F(2)
  F(3)
  F(4)
  F(5)
  F(6)
  F(7)
  F(8)
  F(9)
  F(10)
  F(11)
  F(12)
  F(13)
  F(14)
  F(15)
  return (1 & ((differentbits - 1) >> 8)) - 1;
}

int crypto_aead_decrypt(
  uint8_t *m,size_t *outputmlen,
  const uint8_t *c,size_t clen,
  const uint8_t *ad,size_t adlen,
  const uint8_t *npub,
  const uint8_t *k
)
{
  uint8_t kcopy[16];
  uint8_t H[16];
  uint8_t J[16];
  uint8_t T[16];
  uint8_t accum[16];
  uint8_t stream[16];
  uint8_t finalblock[16];
  size_t mlen;
  size_t origmlen;
  size_t index;
  size_t i;
  const uint8_t *origc;

  for (i = 0;i < 16;++i) kcopy[i] = k[i];

  if (clen < 16) return -1;
  mlen = clen - 16;

  store64(finalblock,8 * adlen);
  store64(finalblock + 8,8 * mlen);

  AES(H,zero,kcopy);

  for (i = 0;i < 12;++i) J[i] = npub[i];
  index = 1;
  store32(J + 12,index);
  AES(T,J,kcopy);

  for (i = 0;i < 16;++i) accum[i] = 0;

  while (adlen > 0) {
    size_t blocklen = 16;
    if (adlen < blocklen) blocklen = adlen;
    addmul(accum,ad,blocklen,H);
    ad += blocklen;
    adlen -= blocklen;
  }

  origc = c;
  origmlen = mlen;
  while (mlen > 0) {
    size_t blocklen = 16;
    if (mlen < blocklen) blocklen = mlen;
    addmul(accum,c,blocklen,H);
    c += blocklen;
    mlen -= blocklen;
  }

  addmul(accum,finalblock,16,H);
  for (i = 0;i < 16;++i) accum[i] ^= T[i];
  if (crypto_verify_16(accum,c) != 0) return -1;

  c = origc;
  mlen = origmlen;
  *outputmlen = mlen;

  while (mlen > 0) {
    size_t blocklen = 16;
    if (mlen < blocklen) blocklen = mlen;
    ++index;
    store32(J + 12,index);
    AES(stream,J,kcopy);
    for (i = 0;i < blocklen;++i) m[i] = c[i] ^ stream[i];
    c += blocklen;
    m += blocklen;
    mlen -= blocklen;
  }

  return 0;
}
