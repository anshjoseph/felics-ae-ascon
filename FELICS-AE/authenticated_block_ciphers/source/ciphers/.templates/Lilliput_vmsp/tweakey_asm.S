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

        push r4                 ; RTK[0..1]
        push r5                 ; RTK[2..3]
        push r6                 ; RTK[4..5]
        push r7                 ; RTK[6..7]

        ;; Set RTK^r to lane 1.
        mov 0(r12), r4
        mov 2(r12), r5
        mov 4(r12), r6
        mov 6(r12), r7

        ;; XOR each 16-bit chunks of TK^r_j to RTK^r.

        ;; j=2
        xor 8(r12), r4
        xor 10(r12), r5
        xor 12(r12), r6
        xor 14(r12), r7

        ;; j=3
        xor 16(r12), r4
        xor 18(r12), r5
        xor 20(r12), r6
        xor 22(r12), r7

        ;; j=4
        xor 24(r12), r4
        xor 26(r12), r5
        xor 28(r12), r6
        xor 30(r12), r7

#if LANES_NB >= 5
        ;; j=5
        xor 32(r12), r4
        xor 34(r12), r5
        xor 36(r12), r6
        xor 38(r12), r7

#if LANES_NB >= 6
        ;; j=6
        xor 40(r12), r4
        xor 42(r12), r5
        xor 44(r12), r6
        xor 46(r12), r7

#if LANES_NB >= 7
        ;; j=7
        xor 48(r12), r4
        xor 50(r12), r5
        xor 52(r12), r6
        xor 54(r12), r7
#endif
#endif
#endif

        ;; Then XOR C^r.
        xor r13, r4

        ;; Commit to r14.
        mov r4, 0(r14)
        mov r5, 2(r14)
        mov r6, 4(r14)
        mov r7, 6(r14)

        pop r7
        pop r6
        pop r5
        pop r4
        ret
