/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu> and 
 * Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

/******************************************************************************* 
 *
 * Cycle count on NRF52840 (hardware)
 *
 ******************************************************************************/

#include <stdint.h>

#ifndef __CYCLE_COUNT_H__
#define __CYCLE_COUNT_H__


// extern uint32_t __cycleCountStart;
// extern uint32_t __cycleCountStop;

// #define CYCLE_COUNT_START \
// 	DWT->CYCCNT = 0x00000000; \
// 	__asm__("nop"); \
// 	__cycleCountStart = DWT->CYCCNT

// #define CYCLE_COUNT_STOP \
// 	__cycleCountStop =  DWT->CYCCNT

// #define CYCLE_COUNT_ELAPSED  (__cycleCountStop - __cycleCountStart)		// -19 ?

// #define CYCLE_COUNT_INIT \
// 	CoreDebug->DEMCR |= 0x01000000; \
// 	DWT->CTRL |= 0x1; \
// 	DWT->CYCCNT = 0x00000000; \
// 	__asm__("nop"); \
//     __cycleCountStart = 0x00000000; \
//     __cycleCountStop = 0x00000000;
// 	//printf("CYCLE_COUNT initialized\r\n");

void cycleCountInit();
void cycleCountStart();
void cycleCountStop();
uint32_t cycleCountElapsed();

#endif /* __CYCLE_COUNT_H__ */
