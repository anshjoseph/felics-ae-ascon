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

#include <stdint.h>
#include "constants.h"
#include "cipher.h"
#include "common.h"

#if defined(NRF52840)
#include "app_uart.h"
#include "app_error.h"
#include "nrf.h"
#include "bsp.h"
#include "nrf_uart.h"
#endif /* NRF52840 */


/* Implementation-checking program. */
int main()
{
        RAM_DATA_BYTE state[MAXTEST_BYTES_M];

        RAM_DATA_BYTE key[KEY_SIZE];

        /* Contains the ciphertext, followed by the tag. */
        RAM_DATA_BYTE c[MAXTEST_BYTES_M+CRYPTO_ABYTES];

        RAM_DATA_BYTE ad[MAXTEST_BYTES_AD];

        RAM_DATA_BYTE npub[CRYPTO_NPUBBYTES];

        InitializeDevice();

        InitializeState(state);
        DisplayVerifyData(state, MAXTEST_BYTES_M, PLAINTEXT_NAME);

        InitializeKey(key);
        DisplayVerifyData(key, KEY_SIZE, KEY_NAME);

        InitializeAd(ad, MAXTEST_BYTES_AD);
        DisplayVerifyData(ad, MAXTEST_BYTES_AD, ASSOCIATED_NAME);

        InitializeNpub(npub);

        BEGIN_ENCRYPTION();
        Encrypt(state, MAXTEST_BYTES_M, key, npub, ad, MAXTEST_BYTES_AD, c);
        END_ENCRYPTION();

        DisplayVerifyData(c, MAXTEST_BYTES_M + CRYPTO_ABYTES, CIPHERTEXT_NAME);

        BEGIN_DECRYPTION();
        int valid = Decrypt(state, MAXTEST_BYTES_M, key, npub, ad, MAXTEST_BYTES_AD, c);
        END_DECRYPTION();

        DisplayVerifyData(state, MAXTEST_BYTES_M, PLAINTEXT_NAME);

        DONE();
        StopDevice();

        return valid;
}
