#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

#include "constants.h"

#define RATE (64 / 8)
#define PA_ROUNDS 12
#define PB_ROUNDS 6

#define ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))

#define EXT_BYTE(x,n) ((uint8_t)((uint64_t)(x)>>(8*(7-(n)))))
#define INS_BYTE(x,n) ((uint64_t)(x)<<(8*(7-(n))))
#define U64BIG(x) \
    ((ROTR(x, 8) & (0xFF000000FF000000ULL)) | \
     (ROTR(x,24) & (0x00FF000000FF0000ULL)) | \
     (ROTR(x,40) & (0x0000FF000000FF00ULL)) | \
     (ROTR(x,56) & (0x000000FF000000FFULL)))

#define ROUND(C) ({\
    x2 ^= C;\
    x0 ^= x4;\
    x4 ^= x3;\
    x2 ^= x1;\
    t0 = x0;\
    t4 = x4;\
    t3 = x3;\
    t1 = x1;\
    t2 = x2;\
    x0 = t0 ^ ((~t1) & t2);\
    x2 = t2 ^ ((~t3) & t4);\
    x4 = t4 ^ ((~t0) & t1);\
    x1 = t1 ^ ((~t2) & t3);\
    x3 = t3 ^ ((~t4) & t0);\
    x1 ^= x0;\
    t1  = x1;\
    x1 = ROTR(x1, R[1][0]);\
    x3 ^= x2;\
    t2  = x2;\
    x2 = ROTR(x2, R[2][0]);\
    t4  = x4;\
    t2 ^= x2;\
    x2 = ROTR(x2, R[2][1] - R[2][0]);\
    t3  = x3;\
    t1 ^= x1;\
    x3 = ROTR(x3, R[3][0]);\
    x0 ^= x4;\
    x4 = ROTR(x4, R[4][0]);\
    t3 ^= x3;\
    x2 ^= t2;\
    x1 = ROTR(x1, R[1][1] - R[1][0]);\
    t0  = x0;\
    x2 = ~x2;\
    x3 = ROTR(x3, R[3][1] - R[3][0]);\
    t4 ^= x4;\
    x4 = ROTR(x4, R[4][1] - R[4][0]);\
    x3 ^= t3;\
    x1 ^= t1;\
    x0 = ROTR(x0, R[0][0]);\
    x4 ^= t4;\
    t0 ^= x0;\
    x0 = ROTR(x0, R[0][1] - R[0][0]);\
    x0 ^= t0;\
  })

#define P12 ({\
  ROUND(0xf0);\
  ROUND(0xe1);\
  ROUND(0xd2);\
  ROUND(0xc3);\
  ROUND(0xb4);\
  ROUND(0xa5);\
  ROUND(0x96);\
  ROUND(0x87);\
  ROUND(0x78);\
  ROUND(0x69);\
  ROUND(0x5a);\
  ROUND(0x4b);\
})

#define P6 ({\
  ROUND(0x96);\
  ROUND(0x87);\
  ROUND(0x78);\
  ROUND(0x69);\
  ROUND(0x5a);\
  ROUND(0x4b);\
})

#endif /* UTILS_H */
