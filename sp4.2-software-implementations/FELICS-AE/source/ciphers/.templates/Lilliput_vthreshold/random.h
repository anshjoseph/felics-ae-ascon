#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>
#include <string.h>


static void randombytes(size_t n, uint8_t output[n])
{
    memset(output, 0x2a, n);
}


#endif /* RANDOM_H */
