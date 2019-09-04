/*
Implementation of the Lilliput-AE tweakable block cipher.

Authors, hereby denoted as "the implementer":
    Kévin Le Gouguec,
    2019.

For more information, feedback or questions, refer to our website:
https://paclido.fr/lilliput-ae

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

This file provides a stub for random byte generation.
*/

#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>
#include <string.h>


static void randombytes(size_t n, uint8_t output[n])
{
    memset(output, 0x2a, n);
}


#endif /* RANDOM_H */
