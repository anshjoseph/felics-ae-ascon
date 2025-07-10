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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "felics/cipher.h"
#include "api.h"
#include "utils.h"

// Rule 90: XOR of left and right
int rule90(int left, int right) {
    return left ^ right;
}

// Rule 150: XOR of left, center, and right
int rule150(int left, int center, int right) {
    return left ^ center ^ right;
}

unsigned int binary_array_to_number(int *array, int size) {
    unsigned int number = 0;
    for (int i = 0; i < size; i++) {
        number = (number << 1) | (array[i] & 1);
    }
    return number;
}

void run_hybrid_automaton(int *state, int *rules, int size, int steps) {
    int current[100], next[100]; // buffer arrays

    // Copy initial state
    for (int i = 0; i < size; i++) {
        current[i] = *(state + i);
    }

    // Simulate for given steps
    for (int step = 1; step <= steps; step++) {
        for (int i = 0; i < size; i++) {
            int left = (i == 0) ? 0 : current[i - 1];
            int center = current[i];
            int right = (i == size - 1) ? 0 : current[i + 1];

            int rule = *(rules + i);

            if (rule == 90) {
                next[i] = rule90(left, right);
            } else if (rule == 150) {
                next[i] = rule150(left, center, right);
            } else {
                next[i] = 0;
            }
        }

        // Copy next to current
        for (int i = 0; i < size; i++) {
            current[i] = next[i];
        }
    }

    // Optional: Update the input state pointer to final state
    for (int i = 0; i < size; i++) {
        *(state + i) = current[i];
    }
}

int STATE1[5] = {0, 1, 0, 0, 1};
int STATE2[5] = {0, 1, 0, 0, 1};
int RULES[5] = {90, 150, 90, 150, 90};
int SIZE = 5;
int STEPS = 10;
int rightRotate(int n, int d) {
    
    // Rotation of 32 is same as rotation of 0
    d = d % 32;
    
    // Picking the leftmost d bits
    int mask = (1 << d) - 1;
    int shift = (n & mask);
    
    // Moving the remaining bits to their new location
    n = (n >> d);
    
    // Adding removed bits at rightmost end
    n += (shift << (32 - d));

    // Ensuring 32-bit constraint
    return n & ((1 << 32) - 1);
}
void crypto_aead_encrypt(
    uint8_t *c, size_t *clen,
    const uint8_t *m, size_t mlen,
    const uint8_t *ad, size_t adlen,
    const uint8_t *npub,
    const uint8_t *k) {

  uint64_t K0 = U64BIG(((uint64_t*)k)[0]);
  uint64_t K1 = U64BIG(((uint64_t*)k)[1]);
  uint64_t N0 = U64BIG(((uint64_t*)npub)[0]);
  uint64_t N1 = U64BIG(((uint64_t*)npub)[1]);
  uint64_t x0, x1, x2, x3, x4;
  uint64_t t0, t1, t2, t3, t4;
  uint64_t rlen;
  size_t i;

  // initialization
  x0 = (uint64_t)((CRYPTO_KEYBYTES * 8) << 24 | (RATE * 8) << 16 | PA_ROUNDS << 8 | PB_ROUNDS << 0) << 32;
  x1 = K0;
  x2 = K1;
  x3 = N0;
  x4 = N1;
  P12;
  x3 ^= K0;
  x4 ^= K1;

  // process associated data
  if (adlen) {
    rlen = adlen;
    while (rlen >= RATE) {
      x0 ^= U64BIG(*(uint64_t*)ad);
      P6;
      rlen -= RATE;
      ad += RATE;
    }
    for (i = 0; i < rlen; ++i, ++ad)
      x0 ^= INS_BYTE(*ad, i);
    x0 ^= INS_BYTE(0x80, rlen);
    P6;
  }
  x4 ^= 1;

  // process plaintext
  rlen = mlen;
  while (rlen >= RATE) {
    x0 ^= U64BIG(*(uint64_t*)m);
    *(uint64_t*)c = U64BIG(x0);
    P6;
    rlen -= RATE;
    m += RATE;
    c += RATE;
  }
  for (i = 0; i < rlen; ++i, ++m, ++c) {
    x0 ^= INS_BYTE(*m, i);
    *c = EXT_BYTE(x0, i);
  }
  x0 ^= INS_BYTE(0x80, rlen);

  // finalization
  x1 ^= K0;
  x2 ^= K1;
  P12;
  x3 ^= K0;
  x4 ^= K1;

  // 1D Cellular Automata
  run_hybrid_automaton(STATE1, RULES, SIZE, STEPS);
  run_hybrid_automaton(STATE2, RULES, SIZE, STEPS);

  unsigned int end_result1 = (1 << 5) | binary_array_to_number(STATE1, SIZE);
  unsigned int end_result2 = binary_array_to_number(STATE2, SIZE);

  x3 = rightRotate(x3, end_result1);
  x4 = rightRotate(x4, end_result2);
  
  // return tag
  ((uint64_t*)c)[0] = U64BIG(x3);
  ((uint64_t*)c)[1] = U64BIG(x4);

  *clen = mlen + CRYPTO_KEYBYTES;
}
