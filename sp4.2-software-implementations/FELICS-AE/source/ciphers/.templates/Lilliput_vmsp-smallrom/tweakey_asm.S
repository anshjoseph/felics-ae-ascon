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

        ;; lane p=0 = TK[0..7] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; Skip this lane, as it is multiplied by the identity matrix.

        ;; lane p=1 = TK[8..15] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        push r12

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

        pop r12

#if LANES_NB >= 5
        ;; lane p=4 = TK[32..39] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov.b 32(r12), r4       ; x0
        mov.b 33(r12), r5       ; x1
        mov.b 34(r12), r6       ; x2
        mov.b 35(r12), r7       ; x3
        mov.b 36(r12), r8       ; x4
        mov.b 37(r12), r9       ; x5
        mov.b 38(r12), r10      ; x6
        mov.b 39(r12), r11      ; x7

        ;; First, store every yj which depends on a single xi.
        mov.b r5, 32(r12)       ; x1 -> y0
        mov.b r6, 33(r12)       ; x2 -> y1
        mov.b r8, 35(r12)       ; x4 -> y3
        mov.b r11, 38(r12)      ; x7 -> y6
        mov.b r4, 39(r12)       ; x0 -> y7

        ;; y2 = x3 ^ x4>>3
        rrl3.b r8
        xor.b r7, r8
        mov.b r8, 34(r12)

        ;; y5 = x3<<2 ^ x6
        rll2.b r7
        xor.b r10, r7
        mov.b r7, 37(r12)

        ;; y4 = x5 ^ x6<<3
        rll3.b r10
        xor.b r9, r10
        mov.b r10, 36(r12)

#if LANES_NB >= 6
        ;; lane p=5 = TK[40..47] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov 40(r12), r4         ; x0, x1
        mov.b 42(r12), r6       ; x2
        mov.b 43(r12), r7       ; x3
        mov.b 44(r12), r8       ; x4
        mov.b 45(r12), r9       ; x5
        mov.b 46(r12), r10      ; x6
        mov.b 47(r12), r11      ; x7

        ;; First, store every yj which depends on a single xi.
        mov.b r6, 40(r12)       ; x2 -> y0
        mov r4, 46(r12)         ; x0,x1 -> y6,y7

        ;; Clobber x0 with x14 = x5 ^ x6<<3
        mov.b r10, r4
        rll3.b r4
        xor.b r9, r4
        ;; y3 = x14
        mov.b r4, 43(r12)
        ;; y2 = x4 ^ x14>>3
        rrl3.b r4
        xor.b r8, r4
        mov.b r4, 42(r12)

        ;; Clobber x0 with x4>>3, since x4 is still needed for y5.
        mov.b r8, r4
        rrl3.b r4
        ;; y1 = x3 ^ x4>>3
        xor.b r7, r4
        mov.b r4, 41(r12)

        ;; y5 = x4<<2 ^ x7
        rll2.b r8
        xor.b r11, r8
        mov.b r8, 45(r12)

        ;; y4 = x3<<2 ^ x6 ^ x7<<3
        rll2.b r7
        rll3.b r11
        xor.b r7, r10
        xor.b r11, r10
        mov.b r10, 44(r12)

#if LANES_NB >= 7
        ;; lane p=6 = TK[48..55] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov.b 48(r12), r4       ; x0
        mov.b 49(r12), r5       ; x1
        mov.b 50(r12), r6       ; x2
        mov.b 51(r12), r7       ; x3
        mov.b 52(r12), r8       ; x4
        mov.b 53(r12), r9       ; x5
        mov.b 54(r12), r10      ; x6
        mov.b 55(r12), r11      ; x7

        ;; First, store every yj which depends on a single xi.
        mov.b r5, 54(r12)       ; x1 -> y6
        mov.b r6, 55(r12)       ; x2 -> y7

        ;; Clobber x1 with y0 = x3 ^ x4>>3
        mov.b r8, r5
        rrl3.b r5
        xor.b r7, r5
        mov.b r5, 48(r12)

        ;; Clobber x1 with x6<<3, then x5 with x14 = x5 ^ x6<<3
        mov.b r10, r5
        rll3.b r5
        xor.b r5, r9

        ;; Clobber x1 with x7<<3, then x3 with x24 = x3<<2 ^ x6 ^ x7<<3
        mov.b r11, r5
        rll3.b r5
        rll2.b r7
        xor.b r5, r7
        xor.b r10, r7

        ;; y3 = x24
        mov.b r7, 51(r12)

        ;; Clobber x24 with y2 = x14 ^ x24>>3
        rrl3.b r7
        xor.b r9, r7
        mov.b r7, 50(r12)

        ;; Clobber x2 with x4<<2, x3 with x0<<3
        mov.b r8, r6
        rll2.b r6
        mov.b r4, r7
        rll3.b r7
        ;; Clobber x7 with y4 = x4<<2 ^ x7 ^ x0<<3
        xor.b r6, r11
        xor.b r7, r11
        mov.b r11, 52(r12)

        ;; Clobber x1 with x14<<2
        mov.b r9, r5
        rll2.b r5
        ;; y5 = x14<<2 ^ x0
        xor.b r5, r4
        mov.b r4, 53(r12)

        ;; y1 = x4 ^ x14>>3
        rrl3.b r9
        xor.b r9, r8
        mov.b r8, 49(r12)
#endif
#endif
#endif

        pop r11
        pop r10
        pop r9
        pop r8
        pop r7
        pop r6
        pop r5
        pop r4
        ret
