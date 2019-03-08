/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

#include <stdint.h>

#include "test_vectors.h"


/*
 *
 * Test vectors
 *
 */
/* Replace with the cipher test vectors */
const uint8_t expectedPlaintext[MAXTEST_BYTES_M] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedAssociated[MAXTEST_BYTES_AD] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedKey[KEY_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
/* EXPECTED CIPHERTEXT can be added*/
const uint8_t expectedCiphertext[MAXTEST_BYTES_M + CRYPTO_ABYTES] = {0x10, 0xb0, 0xde, 0xe6, 0x5a, 0x97, 0xd7, 0x51, 0x20, 0x5c, 0x12, 0x8a, 0x99, 0x24, 0x73, 0xa1, 0x46, 0xdc, 0xb9, 0xee, 0x93, 0xc4, 0x6c, 0xf1, 0x37, 0x31, 0xd4, 0x1b, 0x96, 0x46, 0xc1, 0x31};

