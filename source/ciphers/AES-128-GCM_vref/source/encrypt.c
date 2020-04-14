#include <stddef.h>
#include <stdint.h>

#include "common.h"

int crypto_aead_encrypt(
  uint8_t *c,size_t *clen,
  const uint8_t *m,size_t mlen,
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
  size_t i;
  size_t index;

  for (i = 0;i < 16;++i) kcopy[i] = k[i];

  *clen = mlen + 16;
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

  while (mlen > 0) {
    size_t blocklen = 16;
    if (mlen < blocklen) blocklen = mlen;
    ++index;
    store32(J + 12,index);
    AES(stream,J,kcopy);
    for (i = 0;i < blocklen;++i) c[i] = m[i] ^ stream[i];
    addmul(accum,c,blocklen,H);
    c += blocklen;
    m += blocklen;
    mlen -= blocklen;
  }

  addmul(accum,finalblock,16,H);
  for (i = 0;i < 16;++i) c[i] = T[i] ^ accum[i];
  return 0;
}
