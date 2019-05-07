#ifndef AES_COMMON_H
#define AES_COMMON_H

#include <stdint.h>

uint8_t gmul_o(uint8_t a, uint8_t b);

#define GF256MUL_1(a) (a)
#define GF256MUL_2(a) (gmul_o(2, (a)))
#define GF256MUL_3(a) (gmul_o(3, (a)))

void AES_RunKeySchedule(uint8_t *key, uint8_t *roundkeys);


#endif /* AES_COMMON_H */
