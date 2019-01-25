#include "aegis_utils.h"

extern inline void AESROUND(uint8_t *out, uint8_t *in, uint8_t *rk);
extern inline void XOR128(uint8_t *x, const uint8_t *y, const uint8_t *z);
extern inline void AND128(uint8_t *x, const uint8_t *y, const uint8_t *z);
extern inline void msgtmp_init(uint8_t *msgtmp, uint64_t msglen, uint64_t adlen);
