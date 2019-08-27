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

#include <stddef.h>
#include <stdint.h>

#include "felics/cipher.h"
#include "felics/common.h"
#include "crypto_aead.h"
#include "constants.h"

#if defined(PC)
#include <inttypes.h>
#include "cycleCount.h"
#endif /* PC */

#if defined(ARM)
#include <sam3x8e.h>

#if defined(MEASURE_CYCLE_COUNT) && \
	(MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT)
#include <stdio.h>
#endif  /* ARM & MEASURE_CYCLE_COUNT */

#include "cycleCount.h"
#endif /* ARM */

#if defined(NRF52840)
#include "app_uart.h"
#include "app_error.h"
#include "nrf.h"
#include "bsp.h"
#include "nrf_uart.h"
#include "cycleCount.h"
#endif /* NRF52840 */

#if defined(STM32L053) && defined(MEASURE_CYCLE_COUNT) && \
	(MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT)
#include <stdio.h>
#include <stdint.h>
#include "usart.h"
#include "gpio.h"
#include "error_handler.h"
#include "system_clock.h"
#include "cycleCount.h"
#endif /* STM32L053 & MEASURE_CYCLE_COUNT */

#if defined(STM32L053) && defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
#include <stdio.h>
#include <stdint.h>
#include "usart.h"
#include "gpio.h"
#include "error_handler.h"
#include "system_clock.h"
#endif /* STM32L053 & DEBUG */


#define DATA_SIZE 16
#define ASSOCIATED_DATA_SIZE 16


/* Performance-measurement program. */
int main()
{
        RAM_DATA_BYTE data[DATA_SIZE];
        size_t mlen;

        RAM_DATA_BYTE key[KEY_SIZE];

        /* Contains the ciphertext, followed by the tag. */
        RAM_DATA_BYTE c[DATA_SIZE+CRYPTO_ABYTES];
        size_t clen;

        RAM_DATA_BYTE ad[ASSOCIATED_DATA_SIZE];

        RAM_DATA_BYTE npub[CRYPTO_NPUBBYTES];

        InitializeDevice();

        InitializeData(data, DATA_SIZE);
        InitializeKey(key);
        InitializeAd(ad, ASSOCIATED_DATA_SIZE);
        InitializeNpub(npub);

        BEGIN_ENCRYPTION();
        crypto_aead_encrypt(c, &clen, data, sizeof(data), ad, sizeof(ad), npub, key);
        END_ENCRYPTION();

        BEGIN_DECRYPTION();
        int valid = crypto_aead_decrypt(data, &mlen, c, clen, ad, sizeof(ad), npub, key);
        END_DECRYPTION();

        DONE();
        StopDevice();

        return valid;
}
