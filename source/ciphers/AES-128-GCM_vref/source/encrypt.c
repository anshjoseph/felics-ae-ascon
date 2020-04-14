#include "common.h"

int crypto_aead_encrypt(
  unsigned char *c,unsigned long long *clen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k
)
{
  unsigned char kcopy[16];
  unsigned char H[16];
  unsigned char J[16];
  unsigned char T[16];
  unsigned char accum[16];
  unsigned char stream[16];
  unsigned char finalblock[16];
  unsigned long long i;
  unsigned long long index;

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
    unsigned long long blocklen = 16;
    if (adlen < blocklen) blocklen = adlen;
    addmul(accum,ad,blocklen,H);
    ad += blocklen;
    adlen -= blocklen;
  }

  while (mlen > 0) {
    unsigned long long blocklen = 16;
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
