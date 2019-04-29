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


        ;; TODO: check whether some intermediate variables could be
        ;; replaced with dedicated instructions; eg for MR^2, maybe it
        ;; is more efficient to bic x6 instead of <<3 then >>3 for y2.

        .global tweakey_state_update_asm
        .type tweakey_state_update_asm, @function
tweakey_state_update_asm:
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
        mov.b 8(r12), r4        ; x0
        mov.b 9(r12), r5        ; x1
        mov.b 10(r12), r6       ; x2
        mov.b 11(r12), r7       ; x3
        mov.b 12(r12), r8       ; x4
        mov.b 13(r12), r9       ; x5
        mov.b 14(r12), r10      ; x6
        mov.b 15(r12), r11      ; x7

        ;; First, store every yj which depends on a single xi.
        mov.b r10, 15(r12)      ; x6 -> y7
        mov.b r9, 14(r12)       ; x5 -> y6
        mov.b r6, 11(r12)       ; x2 -> y3
        mov.b r4, 9(r12)        ; x0 -> y1
        mov.b r11, 8(r12)       ; x7 -> y0

        ;; y5 = x5<<3 ^ x4
        rla.b r9
        rla.b r9
        rla.b r9
        xor.b r8, r9
        mov.b r9, 13(r12)

        ;; y4 = x4>>3 ^ x3
        rra.b r8
        rra.b r8
        rra.b r8
        bic.b #0b11100000, r8
        xor.b r7, r8
        mov.b r8, 12(r12)

        ;; y2 = x6<<2 ^ x1
        rla.b r10
        rla.b r10
        xor.b r5, r10
        mov.b r10, 10(r12)

        ;; lane p=2 = TK[16..23] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov.b 16(r12), r4       ; x0
        mov.b 17(r12), r5       ; x1
        mov.b 18(r12), r6       ; x2
        mov.b 19(r12), r7       ; x3
        mov.b 20(r12), r8       ; x4
        mov.b 21(r12), r9       ; x5
        mov 22(r12), r10        ; x6, x7

        ;; First, store every yj which depends on a single xi.
        mov.b r9, 23(r12)       ; x5 -> y7
        mov r10, 16(r12)        ; x6, x7 -> y0, y1

        ;; Clobber xi's which are not used anywhere else.
        ;; y3 = x6<<2 ^ x1
        rla.b r10
        rla.b r10
        xor.b r5, r10
        mov.b r10, 19(r12)
        ;; y2 = x5<<2 ^ x0
        rla.b r9
        rla.b r9
        xor.b r9, r4
        mov.b r4, 18(r12)
        ;; NB: we are not done with r9 = x5<<2

        ;; Clobber x5 with x15 = x5<<3 ^ x4
        rla.b r9
        xor.b r8, r9
        ;; y6 = x15
        mov.b r9, 22(r12)

        ;; Clobber x4 with x14 = x4>>3 ^ x3
        rra.b r8
        rra.b r8
        rra.b r8
        bic.b #0b11100000, r8
        xor.b r7, r8
        ;; y5 = x15<<3 ^ x14
        rla.b r9
        rla.b r9
        rla.b r9
        xor.b r8, r9
        mov.b r9, 21(r12)
        ;; y4 = x14>>3 ^ x2
        rra.b r8
        rra.b r8
        rra.b r8
        bic.b #0b11100000, r8
        xor.b r6, r8
        mov.b r8, 20(r12)

        ;; lane p=3 = TK[24..31] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov.b 24(r12), r4       ; x0
        mov.b 25(r12), r5       ; x1
        mov.b 26(r12), r6       ; x2
        mov.b 27(r12), r7       ; x3
        mov.b 28(r12), r8       ; x4
        mov.b 29(r12), r9       ; x5
        mov.b 30(r12), r10      ; x6
        mov.b 31(r12), r11      ; x7

        ;; First, store every yj which depends on a single xi.
        mov.b r10, 25(r12)      ; x6 -> y1
        mov.b r9, 24(r12)       ; x5 -> y0

        ;; x5 is only needed for y3 (<<2) and x15 (<<3).
        ;; y3 = x5<<2 ^ x0
        rla.b r9
        rla.b r9
        xor.b r9, r4
        mov.b r4, 27(r12)

        ;; Clobber x5 with x15 = x5<<3 ^ x4
        rla.b r9
        xor.b r8, r9
        ;; y7 = x15
        mov.b r9, 31(r12)

        ;; x15 is only needed for y2 (<<2) and x25 (<<3).
        ;; y2 = x15<<2 ^ x7
        rla.b r9
        rla.b r9
        xor.b r9, r11
        mov.b r11, 26(r12)

        ;; x15 is now only used for x25 = x15<<3 ^ x14.

        ;; First, compute x14 = x4>>3 ^ x3. Since none of x3 and x4
        ;; are used anywhere else, clobber x4 with x14.
        rra.b r8
        rra.b r8
        rra.b r8
        bic.b #0b11100000, r8
        xor.b r7, r8

        ;; Clobber x15 with x25 = x15<<3 ^ x14
        rla.b r9
        xor.b r8, r9

        ;; y6 = x25
        mov.b r9, 30(r12)

        ;; Clobber x14 with x24 = x14>>3 ^ x2
        rra.b r8
        rra.b r8
        rra.b r8
        bic.b #0b11100000, r8
        xor.b r6, r8

        ;; y5 = x25<<3 ^ x24
        rla.b r9
        rla.b r9
        rla.b r9
        xor.b r8, r9
        mov.b r9, 29(r12)

        ;; y4 = x24>>3 ^ x6<<2 ^ x1
        rra.b r8
        rra.b r8
        rra.b r8
        bic.b #0b11100000, r8
        rla.b r10
        rla.b r10
        xor.b r10, r8
        xor.b r5, r8
        mov.b r8, 28(r12)

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
        rra.b r8
        rra.b r8
        rra.b r8
        bic.b #0b11100000, r8
        xor.b r7, r8
        mov.b r8, 34(r12)

        ;; y5 = x3<<2 ^ x6
        rla.b r7
        rla.b r7
        xor.b r10, r7
        mov.b r7, 37(r12)

        ;; y4 = x5 ^ x6<<3
        rla.b r10
        rla.b r10
        rla.b r10
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

        ;; Clobber x5 with x14 = x5 ^ x6<<3; first clobber x0 with x6<<3.
        mov.b r10, r4
        rla.b r4
        rla.b r4
        rla.b r4
        xor.b r4, r9
        ;; y3 = x14
        mov.b r9, 43(r12)
        ;; y2 = x4 ^ x14>>3
        rra.b r9
        rra.b r9
        rra.b r9
        bic.b #0b11100000, r9
        xor.b r8, r9
        mov.b r9, 42(r12)

        ;; Clobber x5 with x4>>3, since x4 is still needed for y5.
        mov.b r8, r9
        rra.b r9
        rra.b r9
        rra.b r9
        bic.b #0b11100000, r9
        ;; y1 = x3 ^ x4>>3
        xor.b r7, r9
        mov.b r9, 41(r12)

        ;; y5 = x4<<2 ^ x7
        rla.b r8
        rla.b r8
        xor.b r11, r8
        mov.b r8, 45(r12)

        ;; y4 = x3<<2 ^ x6 ^ x7<<3
        rla.b r7
        rla.b r7
        rla.b r11
        rla.b r11
        rla.b r11
        xor.b r7, r10
        xor.b r11, r10
        mov.b r10, 44(r12)
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
