#include <stdint.h>
#include <string.h>

#include "aes_common.h"
#include "constants.h"


uint8_t gmul_o(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    uint8_t counter;
    uint8_t hi_bit_set;

    for (counter = 0; counter < 8; counter++)
    {
        if ((b & 1) == 1)
        {
            p ^= a;
        }
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80)
        {
            a ^= 0x1b;
        }
        b >>= 1;
    }

    return p;
}

static void aes_rotword(uint8_t *a)
{
	uint8_t t;

	
	t = a[0];
	a[0] = a[1];
	a[1] = a[2];
	a[2] = a[3];
	a[3] = t;
}

void AES_RunKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t i;
	uint8_t rc = 0;

	union {
		uint32_t v32;
		uint8_t v8[4];
	} tmp;


	memcpy(roundKeys, key, 16);

	for (i = 4; i < 44; ++i) 
	{
		tmp.v32 = ((uint32_t*)(roundKeys))[i - 1];
		if (0 == i % 4)
		{
			aes_rotword((uint8_t*)&(tmp.v32));
			
			tmp.v8[0] = READ_SBOX_BYTE(sbox[tmp.v8[0]]);
			tmp.v8[1] = READ_SBOX_BYTE(sbox[tmp.v8[1]]);
			tmp.v8[2] = READ_SBOX_BYTE(sbox[tmp.v8[2]]);
			tmp.v8[3] = READ_SBOX_BYTE(sbox[tmp.v8[3]]);
			tmp.v8[0] ^= READ_KS_BYTE(rc_tab[rc]);
			rc++;
		}
		((uint32_t*)(roundKeys))[i] = ((uint32_t*)(roundKeys))[i - 4]
			^ tmp.v32;
	}
}
