#include <stdint.h>
#include <string.h>

#include "crypto_aead.h"

#include "common.h"

/* full AES-GCM decryption function
   basically the same as encrypt, but the checksuming
   is done _before_ the decryption. And checksum is
   checked at the end.
 */
int crypto_aead_decrypt(
  uint8_t *m,size_t *mlen,
  const uint8_t *c,size_t clen,
  const uint8_t *ad,size_t adlen_,
  const uint8_t *npub,
  const uint8_t *k
)
{
  __m128i rkeys[11];
  unsigned long long i, j;
  unsigned long long adlen = adlen_;
  ALIGN16 unsigned char n2[16];
  ALIGN16 unsigned char H[16];
  ALIGN16 unsigned char T[16];
  ALIGN16 unsigned char accum[16];
  ALIGN16 unsigned char fb[16];
  aesni_key128_expand(k, rkeys);
  for (i = 0;i < 12;i++) n2[i] = npub[i];
  for (i = 12; i < 16;i++) n2[i] = 0;
  memset(accum, 0, 16);

  *mlen = clen - 16;

  aesni_encrypt1(H, accum /* only because it's zero */, rkeys);
  n2[15]++;
  aesni_encrypt1(T, n2, rkeys);
  
  (*(unsigned long long*)&fb[0]) = _bswap64((unsigned long long)(8*adlen));
  (*(unsigned long long*)&fb[8]) = _bswap64((unsigned long long)(8*(*mlen)));
  
  const __m128i rev = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);

  __m128i Hv = _mm_shuffle_epi8(_mm_load_si128((const __m128i*)H), rev);
  _mm_store_si128((__m128i*)H,Hv);
  __m128i H2v = mulv(Hv, Hv);
  __m128i H3v = mulv(H2v, Hv);
  __m128i H4v = mulv(H3v, Hv);
#ifdef ACCBY8
  __m128i H5v = mulv(H4v, Hv);
  __m128i H6v = mulv(H5v, Hv);
  __m128i H7v = mulv(H6v, Hv);
  __m128i H8v = mulv(H7v, Hv);
#endif
  __m128i accv = _mm_loadu_si128((const __m128i*)accum);

#ifdef ACCBY8
  /* unrolled by 8 GCM */
  unsigned long long adlen_rnd128 = adlen & ~127ull;
  for (i = 0 ; i < adlen_rnd128 ; i+= 128) {
    __m128i X8 = _mm_loadu_si128((const __m128i*)(ad+i+ 0));
    __m128i X7 = _mm_loadu_si128((const __m128i*)(ad+i+16));
    __m128i X6 = _mm_loadu_si128((const __m128i*)(ad+i+32));
    __m128i X5 = _mm_loadu_si128((const __m128i*)(ad+i+48));
    __m128i X4 = _mm_loadu_si128((const __m128i*)(ad+i+64));
    __m128i X3 = _mm_loadu_si128((const __m128i*)(ad+i+80));
    __m128i X2 = _mm_loadu_si128((const __m128i*)(ad+i+96));
    __m128i X1 = _mm_loadu_si128((const __m128i*)(ad+i+112));
    accv = reduce8(Hv, H2v, H3v, H4v, H5v, H6v, H7v, H8v,
                   X1, X2, X3, X4, X5, X6, X7, X8, accv);
  }
  _mm_storeu_si128((__m128i*)accum, accv);

  /* GCM remainder loop */
  for (i = adlen_rnd128 ; i < adlen ; i+= 16) {
    unsigned long long blocklen = 16;
    if (i+blocklen>adlen)
      blocklen=adlen-i;
    addmul(accum,ad+i,blocklen,H);
  }
#else
  unsigned long long adlen_rnd64 = adlen & ~63ull;
  for (i = 0 ; i < adlen_rnd64 ; i+= 64) {
    __m128i X4 = _mm_loadu_si128((const __m128i*)(ad+i+ 0));
    __m128i X3 = _mm_loadu_si128((const __m128i*)(ad+i+16));
    __m128i X2 = _mm_loadu_si128((const __m128i*)(ad+i+32));
    __m128i X1 = _mm_loadu_si128((const __m128i*)(ad+i+48));
    accv = reduce4(Hv, H2v, H3v, H4v, X1, X2, X3, X4, accv);
  }
  _mm_storeu_si128((__m128i*)accum, accv);

  for (i = adlen_rnd64 ; i < adlen ; i+= 16) {
    unsigned long long blocklen = 16;
    if (i+blocklen>adlen)
      blocklen=adlen-i;
    addmul(accum,ad+i,blocklen,H);
  }
#endif

  unsigned long long mlen_rnd128  = *mlen & ~127ull;

#ifdef ACCBY8
#define LOOPDRND128                                                     \
  {const int iter = 8;                                                  \
    const int lb = iter * 16;                                           \
    for (i = 0 ; i < mlen_rnd128 ; i+= lb) {                            \
      aesni_decrypt8full(m+i, (unsigned int*)n2, rkeys, c+i, accum, Hv, H2v, H3v, H4v, H5v, H6v, H7v, H8v); \
    }}
#else
#define LOOPDRND128                                                     \
  {const int iter = 8;                                                  \
    const int lb = iter * 16;                                           \
    for (i = 0 ; i < mlen_rnd128 ; i+= lb) {                            \
      aesni_decrypt8full(m+i, (unsigned int*)n2, rkeys, c+i, accum, Hv, H2v, H3v, H4v); \
    }}
#endif
  
#define LOOPDRMD128                                       \
  {const int iter = 8;                                    \
    const int lb = iter * 16;                             \
    for (i = mlen_rnd128 ; i < *mlen ; i+= lb) {          \
    ALIGN16 unsigned char outni[lb];                      \
    unsigned long long mj = lb;                           \
    if ((i+mj)>=*mlen)                                    \
      mj = *mlen-i;                                       \
    for (j = 0 ; j < mj ; j+=16) {                        \
      unsigned long long bl = 16;                         \
      if (j+bl>=mj) {                                     \
        bl = mj-j;                                        \
      }                                                   \
      addmul(accum,c+i+j,bl,H);                           \
    }                                                     \
    aesni_encrypt8(outni, (unsigned int*)n2, rkeys);      \
    for (j = 0 ; j < mj ; j++)                            \
      m[i+j] = c[i+j] ^ outni[j];                         \
  }}
  
#define LOOPD(iter)                                       \
  const int lb = iter * 16;                               \
  for (i = 0 ; i < *mlen ; i+= lb) {                      \
    ALIGN16 unsigned char outni[lb];                      \
    unsigned long long mj = lb;                           \
    if ((i+mj)>=*mlen)                                    \
      mj = *mlen-i;                                       \
    for (j = 0 ; j < mj ; j+=16) {                        \
      unsigned long long bl = 16;                         \
      if (j+bl>=mj) {                                     \
        bl = mj-j;                                        \
      }                                                   \
      addmul(accum,c+i+j,bl,H);                           \
    }                                                     \
    aesni_encrypt##iter(outni, (unsigned int*)n2, rkeys);                \
    for (j = 0 ; j < mj ; j++)                            \
      m[i+j] = c[i+j] ^ outni[j];                         \
  }
  
  n2[15]=0;
  incle(n2);
  incle(n2);
  LOOPDRND128;
  LOOPDRMD128;
/*   LOOPD(8); */

  addmul(accum,fb,16,H);

  unsigned char F = 0;

  for (i = 0;i < 16;++i) F |= (c[i+(*mlen)] != (T[i] ^ accum[15-i]));
  if (F)
    return -111;

  return 0; 
}
