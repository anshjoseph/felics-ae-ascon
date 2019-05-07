#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

#include "constants.h"

#define RATE (128 / 8)
#define PA_ROUNDS 12
#define PB_ROUNDS 8


#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))

#define EXT_BYTE32(x,n) ((uint8_t)((uint32_t)(x)>>(8*(3-(n)))))
#define INS_BYTE32(x,n) ((uint32_t)(x)<<(8*(3-(n))))
#define U32BIG(x) \
    ((ROTR32(x,  8) & (0xFF00FF00)) | \
    ((ROTR32(x, 24) & (0x00FF00FF))))

#define EXPAND_SHORT(x) ({\
    x &= 0x0000ffff;\
    x = (x | (x << 8)) & 0x00ff00ff;\
    x = (x | (x << 4)) & 0x0f0f0f0f;\
    x = (x | (x << 2)) & 0x33333333;\
    x = (x | (x << 1)) & 0x55555555;\
    })

#define EXPAND_U32(var,var_o,var_e) ({\
   /*var 32-bit, and var_o/e 16-bit*/\
   t0_e = (var_e);\
   t0_o = (var_o);\
   EXPAND_SHORT(t0_e);\
   EXPAND_SHORT(t0_o);\
   var = t0_e | (t0_o << 1);\
   })


#define COMPRESS_LONG(x) ({\
    x &= 0x55555555;\
    x = (x | (x >> 1)) & 0x33333333;\
    x = (x | (x >> 2)) & 0x0f0f0f0f;\
    x = (x | (x >> 4)) & 0x00ff00ff;\
    x = (x | (x >> 8)) & 0x0000ffff;\
    })


#define COMPRESS_U32(var,var_o,var_e) ({\
  /*var 32-bit, and var_o/e 16-bit*/\
  var_e = var;\
  var_o = var_e >> 1;\
  COMPRESS_LONG(var_e);\
  COMPRESS_LONG(var_o);\
  })

#define COMPRESS_BYTE_ARRAY(a,var_o,var_e) ({\
   var_e = U32BIG(((uint32_t*)(a))[1]);\
   var_o = var_e >> 1;\
   COMPRESS_LONG(var_e);\
   COMPRESS_LONG(var_o);\
   t1_e = U32BIG(((uint32_t*)(a))[0]);\
   t1_o = t1_e >> 1;\
   COMPRESS_LONG(t1_e);\
   COMPRESS_LONG(t1_o);\
   var_e |= t1_e << 16;\
   var_o |= t1_o << 16;\
   })

#define ROUND_32(C_e,C_o) ({\
    /* round constant */\
    x2_e ^= C_e;\
    x2_o ^= C_o;\
    /* s-box layer */\
    t0_e = x0_e ^ x4_e;       t1_e = x4_e ^ x3_e;    x2_e = x2_e ^ x1_e;\
    t0_o = x0_o ^ x4_o;       t1_o = x4_o ^ x3_o;    x2_o = x2_o ^ x1_o;\
    x0_e = x2_e & (~x1_e);    x0_e = t0_e ^ x0_e; \
    x0_o = x2_o & (~x1_o);    x0_o = t0_o ^ x0_o; \
    x4_e = x2_e & (~x1_e);    x4_e = x0_e ^ x4_e;\
    x4_o = x2_o & (~x1_o);    x4_o = x0_o ^ x4_o;\
    x4_e = x1_e & (~x4_e);    x4_e = x4_e ^ t1_e;\
    x4_o = x1_o & (~x4_o);    x4_o = x4_o ^ t1_o;\
    t0_e = x2_e & (~x1_e);    t0_e = t0_e ^ x0_e;\
    t0_o = x2_o & (~x1_o);    t0_o = t0_o ^ x0_o;\
    t0_e = t0_e & (~t1_e);    t0_e = t0_e ^ x3_e;\
    t0_o = t0_o & (~t1_o);    t0_o = t0_o ^ x3_o;\
    t1_e = x2_e & (~x1_e);    t1_e = t1_e ^ x0_e;\
    t1_o = x2_o & (~x1_o);    t1_o = t1_o ^ x0_o;\
    t1_e = x1_e & (~t1_e);    t1_e = t1_e ^ x4_e;\
    t1_o = x1_o & (~t1_o);    t1_o = t1_o ^ x4_o;\
    t1_e = t1_e & (~x3_e);    t1_e = t1_e ^ x2_e;\
    t1_o = t1_o & (~x3_o);    t1_o = t1_o ^ x2_o;\
    x2_e = x3_e & (~x2_e);    x1_e = x1_e ^ x2_e;\
    x2_o = x3_o & (~x2_o);    x1_o = x1_o ^ x2_o;\
    x1_e = x1_e ^ x0_e;    x0_e = x0_e ^ x4_e;    x3_e = t0_e ^ t1_e;    x2_e =~ t1_e;\
    x1_o = x1_o ^ x0_o;    x0_o = x0_o ^ x4_o;    x3_o = t0_o ^ t1_o;    x2_o =~ t1_o;\
    /* linear layer */\
    t0_e  = x0_e;    t0_o  = x0_o; \
    t1_e  = x1_e;    t1_o  = x1_o;\
    x0_e ^= ROTR32(t0_o, R_O[0][0]);\
    x0_o ^= ROTR32(t0_e, R_E[0][0]);\
    x1_e ^= ROTR32(t1_o, R_O[1][0]);\
    x1_o ^= ROTR32(t1_e, R_E[1][0]);\
    x0_e ^= ROTR32(t0_e, R_E[0][1]);\
    x0_o ^= ROTR32(t0_o, R_O[0][1]);\
    x1_e ^= ROTR32(t1_o, R_O[1][1]);\
    x1_o ^= ROTR32(t1_e, R_E[1][1]);\
    t0_e  = x2_e;    t0_o  = x2_o;\
    t1_e  = x3_e;    t1_o  = x3_o;\
    x2_e ^= ROTR32(t0_o, R_O[2][0]);\
    x2_o ^= ROTR32(t0_e, R_E[2][0]);\
    x3_e ^= ROTR32(t1_e, R_E[3][0]);\
    x3_o ^= ROTR32(t1_o, R_O[3][0]);\
    x2_e ^= ROTR32(t0_e, R_E[2][1]);\
    x2_o ^= ROTR32(t0_o, R_O[2][1]);\
    x3_e ^= ROTR32(t1_o, R_O[3][1]);\
    x3_o ^= ROTR32(t1_e, R_E[3][1]);\
    t0_e  = x4_e;\
    t0_o  = x4_o;\
    x4_e ^= ROTR32(t0_o, R_O[4][0]);\
    x4_o ^= ROTR32(t0_e, R_E[4][0]);\
    x4_e ^= ROTR32(t0_o, R_O[4][1]);\
    x4_o ^= ROTR32(t0_e, R_E[4][1]);\
  })

#define P12_32 ({\
  ROUND_32(0xc,0xc);\
  ROUND_32(0x9,0xc);\
  ROUND_32(0xc,0x9);\
  ROUND_32(0x9,0x9);\
  ROUND_32(0x6,0xc);\
  ROUND_32(0x3,0xc);\
  ROUND_32(0x6,0x9);\
  ROUND_32(0x3,0x9);\
  ROUND_32(0xc,0x6);\
  ROUND_32(0x9,0x6);\
  ROUND_32(0xc,0x3);\
  ROUND_32(0x9,0x3);\
})

#define P8_32 ({\
  ROUND_32(0x6,0xc);\
  ROUND_32(0x3,0xc);\
  ROUND_32(0x6,0x9);\
  ROUND_32(0x3,0x9);\
  ROUND_32(0xc,0x6);\
  ROUND_32(0x9,0x6);\
  ROUND_32(0xc,0x3);\
  ROUND_32(0x9,0x3);\
})

#endif /* UTILS_H */
