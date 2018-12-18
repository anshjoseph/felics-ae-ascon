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

#ifndef TEST_VECTORS_H
#define TEST_VECTORS_H

#include "constants.h"

#define MAXTEST_BYTES_M 16
#define MAXTEST_BYTES_AD 16

/*
 *
 * Test vectors
 *
 */
extern const uint8_t expectedPlaintext[MAXTEST_BYTES_M];
extern const uint8_t expectedAssociated[MAXTEST_BYTES_AD];
extern const uint8_t expectedKey[KEY_SIZE];
extern const uint8_t expectedCiphertext[MAXTEST_BYTES_M  + CRYPTO_ABYTES];

#endif /* TEST_VECTORS_H */

