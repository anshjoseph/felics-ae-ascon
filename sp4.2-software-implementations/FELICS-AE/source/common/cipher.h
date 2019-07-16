/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu> and 
 * Yann Le Corre <yann.lecorre@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef CIPHER_H
#define CIPHER_H


#include <stddef.h>
#include <stdint.h>


#ifdef AVR /* AVR */
#include <avr/pgmspace.h>
#endif /* AVR */


/*
 * 
 * SCENARIO values:
 * ... SCENARIO_1 1 - scenario 1: full encryption of 128-bit PT with 128-bit AD
 *
 */
#define SCENARIO_1 1

#ifndef SCENARIO
#define SCENARIO SCENARIO_0
#endif


/*
 *
 * MEASURE_CYCLE_COUNT values:
 * ... MEASURE_CYCLE_COUNT_DISABLED 0 - measure cycle count is disabled
 * ... MEASURE_CYCLE_COUNT_ENABLED 1 - measure cycle count is enabled
 *
 */
#define MEASURE_CYCLE_COUNT_DISABLED 0
#define MEASURE_CYCLE_COUNT_ENABLED 1

#ifndef MEASURE_CYCLE_COUNT
#define MEASURE_CYCLE_COUNT MEASURE_CYCLE_COUNT_DISABLED
#endif


/*
 *
 * Align memory boundaries in bytes
 *
 */
#if defined(AVR)
#define ALIGNMENT 1

#elif defined(MSP)
#define ALIGNMENT 2

#elif defined(ARM)
#define ALIGNMENT 8

#elif defined(PC)
#define ALIGNMENT 8

#elif defined(NRF52840)
#define ALIGNMENT 8

#else
#error "No architecture defined; expected one of AVR, MSP, ARM or PC."
#endif

#define ALIGNED __attribute__ ((aligned(ALIGNMENT)))

#if defined(NRF52840) && !defined(ALIGNED) /* NRF52840 ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_NRF52840_BOUNDRY)))
#endif /* NRF52840 ALIGNED */


/* 
 *
 * RAM data types 
 *
 */
#define RAM_DATA_BYTE uint8_t ALIGNED
#define RAM_DATA_WORD uint16_t ALIGNED
#define RAM_DATA_DOUBLE_WORD uint32_t ALIGNED

#define READ_RAM_DATA_BYTE(x) x
#define READ_RAM_DATA_WORD(x) x
#define READ_RAM_DATA_DOUBLE_WORD(x) x


/* 
 *
 * Flash/ROM data types 
 *
 */
#if defined(AVR) /* AVR */
#define ROM_DATA_BYTE const uint8_t PROGMEM ALIGNED
#define ROM_DATA_WORD const uint16_t PROGMEM ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t PROGMEM ALIGNED

#define READ_ROM_DATA_BYTE(x) pgm_read_byte(&x)
#define READ_ROM_DATA_WORD(x) pgm_read_word(&x)
#define READ_ROM_DATA_DOUBLE_WORD(x) pgm_read_dword(&x)

#define ROM_memcpy memcpy_P

#else /* AVR */
#define ROM_DATA_BYTE const uint8_t ALIGNED
#define ROM_DATA_WORD const uint16_t ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t ALIGNED

#define READ_ROM_DATA_BYTE(x) x
#define READ_ROM_DATA_WORD(x) x
#define READ_ROM_DATA_DOUBLE_WORD(x) x

#define ROM_memcpy memcpy

#endif /* AVR */


/*
 *
 * Encrypt the given block using the given round keys
 * ... block - the block to encrypt
 *
 */
void Encrypt(uint8_t *block, size_t mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t adlen, uint8_t *c);

/*
 *
 * Decrypt the given block using the given round keys
 * ... block - the block to decrypt
 *
 */
int Decrypt(uint8_t *block, size_t mlen, uint8_t *key, uint8_t *npub,
 uint8_t *ad, size_t adlen, uint8_t *c);

#endif /* CIPHER_H */
