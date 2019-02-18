#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#include "data_types.h"


void G(uint8_t tweakey[], uint8_t alpha);
void H(uint8_t tweakey[]);

void set_nonce_in_tweak(uint8_t *tweak, const uint8_t *nonce);
void set_block_number_in_tweak(uint8_t *tweak, int64_t block_no);
void set_stage_in_tweak(uint8_t *tweak, const uint8_t value);
void set_tweak_in_tweakey(uint8_t *tweakey, uint8_t *tweak);

void xor_values(uint8_t *v1, const uint8_t *v2);

void aesTweakEncrypt(uint32_t tweakey_size,
                     const uint8_t pt[16],
                     const uint8_t key[],
                     uint8_t ct[16]);

int deoxysKeySetupEnc256(uint32_t* rtweakey,
                         const uint8_t* TweakKey,
                         const int no_tweakeys);

#define GETRCON(r) ( ((uint32_t)READ_RCON_BYTE(rcon[r])<<24) ^ ((uint32_t)READ_RCON_BYTE(rcon[r])<<16) ^ ((uint32_t)READ_RCON_BYTE(rcon[r])<<8) ^ ((uint32_t)READ_RCON_BYTE(rcon[r])<<0) )
#define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] <<  8) ^ ((uint32_t)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (uint8_t)((st) >> 24); (ct)[1] = (uint8_t)((st) >> 16); (ct)[2] = (uint8_t)((st) >>  8); (ct)[3] = (uint8_t)(st); }

#endif /* COMMON_H */
