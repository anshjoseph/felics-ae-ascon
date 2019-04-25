#include "parameters.h"
#define LANE_BITS  64
#define LANE_BYTES (LANE_BITS/8)
#define LANES_NB   (TWEAKEY_BYTES/LANE_BYTES)

        .section .text

        .global tweakey_state_extract
        .type tweakey_state_extract, @function
tweakey_state_extract:
        ;; r12: TK^r
        ;; r13: C^r = r
        ;; r14: RTK^r

        ;; TODO: compute RTK^r in registers, *then* commit to r14.

        ;; Set RTK^r to lane 1.
        mov 0(r12), 0(r14)
        mov 2(r12), 2(r14)
        mov 4(r12), 4(r14)
        mov 6(r12), 6(r14)

        ;; XOR each 16-bit chunks of TK^r_j to RTK^r.

        ;; j=2
        xor 8(r12), 0(r14)
        xor 10(r12), 2(r14)
        xor 12(r12), 4(r14)
        xor 14(r12), 6(r14)

        ;; j=3
        xor 16(r12), 0(r14)
        xor 18(r12), 2(r14)
        xor 20(r12), 4(r14)
        xor 22(r12), 6(r14)

        ;; j=4
        xor 24(r12), 0(r14)
        xor 26(r12), 2(r14)
        xor 28(r12), 4(r14)
        xor 30(r12), 6(r14)

#if LANES_NB >= 5
        ;; j=5
        xor 32(r12), 0(r14)
        xor 34(r12), 2(r14)
        xor 36(r12), 4(r14)
        xor 38(r12), 6(r14)

#if LANES_NB >= 6
        ;; j=6
        xor 40(r12), 0(r14)
        xor 42(r12), 2(r14)
        xor 44(r12), 4(r14)
        xor 46(r12), 6(r14)

#if LANES_NB >= 7
        ;; j=7
        xor 48(r12), 0(r14)
        xor 50(r12), 2(r14)
        xor 52(r12), 4(r14)
        xor 54(r12), 6(r14)
#endif
#endif
#endif

        ;; Then XOR C^r.
        xor.b r13, 0(r14)

        ret
