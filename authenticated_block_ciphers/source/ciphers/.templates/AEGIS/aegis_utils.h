#ifndef AEGIS_UTILS_H
#define AEGIS_UTILS_H

#include "constants.h"


/* NB: this function used to make heavy use of uint8_t* => uint32_t*
 * casts, which broke due to some SSE-related gcc optimization. The
 * problem could be workd around by
 *
 * * adding __attribute__ ((target("no-sse"))) to this function
 * * compiling with -fsanitize=alignment
 *
 * Following advice from [1], I figure memcpy(3) is the way to go.
 *
 * [1]: http://pzemtsov.github.io/2016/11/06/bug-story-alignment-on-x86.html
 */
static inline void AESROUND(uint8_t *out, uint8_t *in, uint8_t *rk)
{
    RAM_DATA_DOUBLE_WORD out32[4];

    for (size_t i=0; i<4; i++)
    {
        memcpy(out32+i, rk+4*i, 4);

        for (size_t j=0; j<4; j++)
        {
            size_t in_index = 4*i+5*j & 0xf;
            size_t TE_index = 4*in[in_index];

            RAM_DATA_DOUBLE_WORD TEj_32;
            ROM_memcpy(&TEj_32, &TE[j][TE_index], 4);

            out32[i] ^= TEj_32;
        }
    }

    memcpy(out, out32, sizeof(out32));
}

static inline void XOR128(uint8_t *x, const uint8_t *y, const uint8_t *z)
{
    uint64_t x64[2], y64[2], z64[2];
    memcpy(y64, y, 16);
    memcpy(z64, z, 16);

    x64[0] = y64[0] ^ z64[0];
    x64[1] = y64[1] ^ z64[1];

    memcpy(x, x64, 16);
}

static inline void AND128(uint8_t *x, const uint8_t *y, const uint8_t *z)
{
    uint64_t x64[2], y64[2], z64[2];
    memcpy(y64, y, 16);
    memcpy(z64, z, 16);

    x64[0] = y64[0] & z64[0];
    x64[1] = y64[1] & z64[1];

    memcpy(x, x64, 16);
}

#endif /* AEGIS_UTILS_H */
