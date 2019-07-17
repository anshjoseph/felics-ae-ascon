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
#include <stdlib.h>
#include <string.h>


#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG)) /* DEBUG */

#include <stdio.h>

#ifdef AVR /* AVR */
#include <avr/io.h>
#include <avr/sleep.h>

#include "avr_mcu_section.h"

#ifndef F_CPU
#define F_CPU (8000000UL)
#endif

#endif /* AVR */

#endif /* DEBUG */


#ifdef MSP /* MSP */
#include <msp430.h>
#endif /* MSP */

#ifdef NRF52840 /* NRF52840 */
#include "app_uart.h"
#include "app_error.h"
#include "nrf.h"
#include "bsp.h"
#include "nrf_uart.h"
#if (MEASURE_CYCLE_COUNT == 1)
#include "cycleCount.h"
#endif
#endif /* NRF52840 */


#include "cipher.h"
#include "common.h"
#include "constants.h"
#include "test_vectors.h"



#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))

const char *KEY_NAME = "Key";
const char *PLAINTEXT_NAME = "Plaintext";
const char *CIPHERTEXT_NAME = "Ciphertext";
const char *ASSOCIATED_NAME = "AssociatedData";

void DisplayData(uint8_t *data, uint16_t length, const char *name)
{
	uint16_t i;

	printf("%s:\n", name);
    for (i = 0; i < length; i++) 
    {
        printf("%02x ", data[i]);
    }
	printf("\n");
}

void DisplayVerifyData(uint8_t *data, uint16_t length, const char *name)
{
	DisplayData(data, length, name);
	VerifyData(data, name);
}

#if defined(AVR) || defined(MSP) || defined(NRF52840)
static void _die(void)
{
	StopDevice();
}
#else
static void _die(void)
{
	exit(1);
}
#endif

void VerifyData(uint8_t *data, const char *name)
{
	uint8_t correct = 1;
	uint16_t length = 0;
	uint16_t i;

	const uint8_t *expectedData;

	
	if(0 == strcmp(name, PLAINTEXT_NAME))
	{
		expectedData = expectedPlaintext;
		length = MAXTEST_BYTES_M;
	}
	
	if(0 == strcmp(name, CIPHERTEXT_NAME))
	{
		expectedData = expectedCiphertext;
		length = MAXTEST_BYTES_M  + CRYPTO_ABYTES;
	}

	if(0 == strcmp(name, KEY_NAME))
	{
		expectedData = expectedKey;
		length = KEY_SIZE;
	}
	
	if(0 == strcmp(name, ASSOCIATED_NAME))
	{
		expectedData = expectedAssociated;
		length = MAXTEST_BYTES_AD;
	}

	if(0 == length)
	{
		return;
	}
	
	
	printf("Expected %s:\n", name);
	for(i = 0; i < length; i++)
	{
		printf("%02x ", expectedData[i]);
		if(expectedData[i] != data[i]) 
		{
			correct = 0;
		}
	}
	printf("\n");
	
	if(correct)
	{
		printf("CORRECT!\n");
	}
	else
	{
		printf("WRONG!\n");
		_die();
	}
}

#endif


void BeginEncryption()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	printf("->Encryption begin\n");
#endif
}

void EndEncryption()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	printf("->Encryption end\n");
#endif
}

void BeginDecryption()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	printf("->Decryption begin\n");
#endif
}

void EndDecryption()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	printf("->Decryption end\n");
#endif
}


#ifdef PC /* PC */

void InitializeDevice()
{

}

void StopDevice()
{
	
}

#endif /* PC */


#ifdef AVR /* AVR */

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG)) /* DEBUG */

AVR_MCU(F_CPU, "atmega128");

static int uart_putchar(char c, FILE *stream)
{
	loop_until_bit_is_set(UCSR0A, UDRE0);
	UDR0 = c;
	
	return 0;
}

static FILE mystdout = FDEV_SETUP_STREAM(uart_putchar, NULL, _FDEV_SETUP_WRITE);
AVR_MCU_SIMAVR_CONSOLE(&UDR0);

#endif /* DEBUG */

void InitializeDevice()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	stdout = &mystdout;
#endif
}

void StopDevice()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	sleep_cpu();
#endif
}

#endif /* AVR */


#ifdef MSP /* MSP */

void InitializeDevice()
{

}

void StopDevice()
{
	
}

#endif /* MSP */


#ifdef ARM /* ARM */

/*
 *
 * init() is defined in the sam3x8e library, so we only need a declaration here
 *
 */
extern void init(void);

void InitializeDevice()
{
	init();
}

void StopDevice()
{
	
}

#endif /* ARM */


#ifdef NRF52840 /* NRF52840 */

#define MAX_TEST_DATA_BYTES     (15U)                /**< max number of test bytes to be used for tx and rx. */
#define UART_TX_BUF_SIZE 2048                         /**< UART TX buffer size. */
#define UART_RX_BUF_SIZE 256                         /**< UART RX buffer size. */
#define UART_HWFC APP_UART_FLOW_CONTROL_DISABLED

void uart_error_handle(app_uart_evt_t * p_event)
{
    if (p_event->evt_type == APP_UART_COMMUNICATION_ERROR)
    {
        APP_ERROR_HANDLER(p_event->data.error_communication);
    }
    else if (p_event->evt_type == APP_UART_FIFO_ERROR)
    {
        APP_ERROR_HANDLER(p_event->data.error_code);
    }
}

void InitializeDevice()
{
	uint32_t err_code;

    const app_uart_comm_params_t comm_params =
      {
          RX_PIN_NUMBER,
          TX_PIN_NUMBER,
          RTS_PIN_NUMBER,
          CTS_PIN_NUMBER,
          UART_HWFC,
          false,
          NRF_UART_BAUDRATE_115200
      };

    APP_UART_FIFO_INIT(&comm_params,
                         UART_RX_BUF_SIZE,
                         UART_TX_BUF_SIZE,
                         uart_error_handle,
                         APP_IRQ_PRIORITY_LOWEST,
                         err_code);

    APP_ERROR_CHECK(err_code);
#if (MEASURE_CYCLE_COUNT == 1)
	cycleCountInit();
#endif
}

void StopDevice()
{
	__WFE();
}

#endif /* NRF52840 */


void InitializeKey(uint8_t *key)
{
	uint8_t i;
	
	for(i = 0; i < KEY_SIZE; i++)
	{
		key[i] = expectedKey[i];
	}
}


void InitializeState(uint8_t *state)
{
	uint32_t i;
	
	for(i = 0; i < MAXTEST_BYTES_M; i++)
	{
		state[i] = expectedPlaintext[i];
	}
}


void InitializeData(uint8_t *data, int length)
{
	int32_t i;
	
	for(i = 0; i < length; i++)
	{
		data[i] = length - i;
	}
}



/* ---------------------------- */
void InitializeAd(uint8_t *ad, int adlen)
{
	int32_t i;
	
	for(i = 0; i < adlen; i++)
	{
		ad[i] = expectedAssociated[i];
	}
}


void InitializeNpub(uint8_t *npub)
{
	uint32_t i;
	
	for(i = 0; i < CRYPTO_NPUBBYTES; i++)
	{
		npub[i] = 0x00;
	}
}




