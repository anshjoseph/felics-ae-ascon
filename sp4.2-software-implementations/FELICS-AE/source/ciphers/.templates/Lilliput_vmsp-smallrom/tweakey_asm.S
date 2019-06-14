#include "parameters.h"

#define LANE_BITS  64
#define LANE_BYTES (LANE_BITS/8)
#define LANES_NB   (TWEAKEY_BYTES/LANE_BYTES)

        .macro rll3.b r
        rla.b \r
        rla.b \r
        rla.b \r
        .endm

        .macro rrl3.b r
        rra.b \r
        rra.b \r
        rra.b \r
        bic.b #0b11100000, \r
        .endm

        .macro rll2.b r
        rla.b \r
        rla.b \r
        .endm


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
        push r8                 ; TK end pointer

        clr r4
        clr r5
        clr r6
        clr r7
        mov r12, r8
        add #(TWEAKEY_BYTES), r8

        ;; XOR all lanes.
_extract_loop:
        xor @r12+, r4
        xor @r12+, r5
        xor @r12+, r6
        xor @r12+, r7

        cmp r8, r12             ; r12-r8
        jl _extract_loop        ; jump if less than 0

        ;; Then XOR C^r.
        xor r13, r4

        ;; Commit to r14.
        mov r4, 0(r14)
        mov r5, 2(r14)
        mov r6, 4(r14)
        mov r7, 6(r14)

        pop r8
        pop r7
        pop r6
        pop r5
        pop r4
        ret


_multiply_M:
        ;; r12: TK_j

        ;; Assume r4 to r11 are pushed and popped by
        ;; tweakey_state_update.

        mov.b 0(r12), r4        ; x0
        mov.b 1(r12), r5        ; x1
        mov.b 2(r12), r6        ; x2
        mov.b 3(r12), r7        ; x3
        mov.b 4(r12), r8        ; x4
        mov.b 5(r12), r9        ; x5
        mov.b 6(r12), r10       ; x6
        mov.b 7(r12), r11       ; x7

        ;; First, store every yj which depends on a single xi.
        mov.b r10, 7(r12)       ; x6 -> y7
        mov.b r9, 6(r12)        ; x5 -> y6
        mov.b r6, 3(r12)        ; x2 -> y3
        mov.b r4, 1(r12)        ; x0 -> y1
        mov.b r11, 0(r12)       ; x7 -> y0

        ;; y5 = x5<<3 ^ x4
        rll3.b r9
        xor.b r8, r9
        mov.b r9, 5(r12)

        ;; y4 = x4>>3 ^ x3
        rrl3.b r8
        xor.b r7, r8
        mov.b r8, 4(r12)

        ;; y2 = x6<<2 ^ x1
        rll2.b r10
        xor.b r5, r10
        mov.b r10, 2(r12)

        ret

#if LANES_NB >= 5
_multiply_MR:
        ;; r12: TK_j

        ;; Assume r4 to r11 are pushed and popped by
        ;; tweakey_state_update.

        mov.b 0(r12), r4        ; x0
        mov.b 1(r12), r5        ; x1
        mov.b 2(r12), r6        ; x2
        mov.b 3(r12), r7        ; x3
        mov.b 4(r12), r8        ; x4
        mov.b 5(r12), r9        ; x5
        mov.b 6(r12), r10       ; x6
        mov.b 7(r12), r11       ; x7

        ;; First, store every yj which depends on a single xi.
        mov.b r5, 0(r12)        ; x1 -> y0
        mov.b r6, 1(r12)        ; x2 -> y1
        mov.b r8, 3(r12)        ; x4 -> y3
        mov.b r11, 6(r12)       ; x7 -> y6
        mov.b r4, 7(r12)        ; x0 -> y7

        ;; y2 = x3 ^ x4>>3
        rrl3.b r8
        xor.b r7, r8
        mov.b r8, 2(r12)

        ;; y5 = x3<<2 ^ x6
        rll2.b r7
        xor.b r10, r7
        mov.b r7, 5(r12)

        ;; y4 = x5 ^ x6<<3
        rll3.b r10
        xor.b r9, r10
        mov.b r10, 4(r12)

        ret
#endif

        .global tweakey_state_update
        .type tweakey_state_update, @function
tweakey_state_update:
        ;; r12: TK
        push r4
        push r5
        push r6
        push r7
        push r8
        push r9
        push r10
        push r11
        push r12

        ;; lane p=0 = TK[0..7] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; Skip this lane, as it is multiplied by the identity matrix.

        ;; lane p=1 = TK[8..15] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        add #8, r12
        call #_multiply_M

        ;; lane p=2 = TK[16..23] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        add #8, r12
        call #_multiply_M
        call #_multiply_M

        ;; lane p=3 = TK[24..31] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        add #8, r12
        call #_multiply_M
        call #_multiply_M
        call #_multiply_M

#if LANES_NB >= 5
        ;; lane p=4 = TK[32..39] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        add #8, r12
        call #_multiply_MR

#if LANES_NB >= 6
        ;; lane p=5 = TK[40..47] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        add #8, r12
        call #_multiply_MR
        call #_multiply_MR

#if LANES_NB >= 7
        ;; lane p=6 = TK[48..55] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        add #8, r12
        call #_multiply_MR
        call #_multiply_MR
        call #_multiply_MR

#endif
#endif
#endif

        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop r7
        pop r6
        pop r5
        pop r4
        ret
