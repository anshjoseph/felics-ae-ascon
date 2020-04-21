;; Implementation of the Lilliput-AE tweakable block cipher.

;; Authors, hereby denoted as "the implementer":
;;     Kévin Le Gouguec,
;;     Gaëtan Leplus,
;;     2019.

;; For more information, feedback or questions, refer to our website:
;; https://paclido.fr/lilliput-ae

;; To the extent possible under law, the implementer has waived all copyright
;; and related or neighboring rights to the source code in this file.
;; http://creativecommons.org/publicdomain/zero/1.0/

;; ---

;; This file provides the implementation of Lilliput-TBC's tweakey schedule.

#include "felics/helpers.S"
#include "constants.h"

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


function tweakey_state_extract
        ;; r12: TK^r
        ;; r13: C^r = r
        ;; r14: RTK^r

        push r4                 ; RTK[0..1]
        push r5                 ; RTK[2..3]
        push r6                 ; RTK[4..5]
        push r7                 ; RTK[6..7]

        ;; Set RTK^r to lane 1.
        mov @r12+, r4
        mov @r12+, r5
        mov @r12+, r6
        mov @r12+, r7

        ;; XOR each 16-bit chunks of TK^r_j to RTK^r.

        ;; j=2
        xor @r12+, r4
        xor @r12+, r5
        xor @r12+, r6
        xor @r12+, r7

        ;; j=3
        xor @r12+, r4
        xor @r12+, r5
        xor @r12+, r6
        xor @r12+, r7

        ;; j=4
        xor @r12+, r4
        xor @r12+, r5
        xor @r12+, r6
        xor @r12+, r7

#if LANES_NB >= 5
        ;; j=5
        xor @r12+, r4
        xor @r12+, r5
        xor @r12+, r6
        xor @r12+, r7

#if LANES_NB >= 6
        ;; j=6
        xor @r12+, r4
        xor @r12+, r5
        xor @r12+, r6
        xor @r12+, r7

#if LANES_NB >= 7
        ;; j=7
        xor @r12+, r4
        xor @r12+, r5
        xor @r12+, r6
        xor @r12+, r7
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


function tweakey_state_update
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
        mov.b @r12+, r4        ; x0
        mov.b  @r12+, r5        ; x1
        mov.b  @r12+, r6       ; x2
        mov.b  @r12+, r7       ; x3
        mov.b  @r12+, r8       ; x4
        mov.b  @r12+, r9       ; x5
        mov.b  @r12+, r10      ; x6
        mov.b  @r12+, r11      ; x7

        ;; First, store every yj which depends on a single xi.
        mov.b r10, -1(r12)      ; x6 -> y7
        mov.b r9, -2(r12)       ; x5 -> y6
        mov.b r6, -5(r12)       ; x2 -> y3
        mov.b r4, -7(r12)        ; x0 -> y1
        mov.b r11, -8(r12)       ; x7 -> y0

        ;; y5 = x5<<3 ^ x4
        rll3.b r9
        xor.b r8, r9
        mov.b r9, -3(r12)

        ;; y4 = x4>>3 ^ x3
        rrl3.b r8
        xor.b r7, r8
        mov.b r8, -4(r12)

        ;; y2 = x6<<2 ^ x1
        rll2.b r10
        xor.b r5, r10
        mov.b r10, -6(r12)

        ;; lane p=1 = TK[8..15] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov.b  @r12+, r4       ; x0
        mov.b  @r12+, r5       ; x1
        mov.b  @r12+, r6       ; x2
        mov.b  @r12+, r7       ; x3
        mov.b  @r12+, r8       ; x4
        mov.b  @r12+, r9       ; x5
        mov  @r12+, r10        ; x6, x7

        ;; First, store every yj which depends on a single xi.
        mov.b r9, -1(r12)       ; x5 -> y7
        mov r10, -8(r12)        ; x6, x7 -> y0, y1

        ;; Clobber xi's which are not used anywhere else.
        ;; y3 = x6<<2 ^ x1
        rll2.b r10
        xor.b r5, r10
        mov.b r10, -5(r12)
        ;; y2 = x5<<2 ^ x0
        rll2.b r9
        xor.b r9, r4
        mov.b r4, -6(r12)
        ;; NB: we are not done with r9 = x5<<2

        ;; Clobber x5 with a5 = x5<<3 ^ x4
        rla.b r9
        xor.b r8, r9
        ;; y6 = a5
        mov.b r9, -2(r12)

        ;; Clobber x4 with a4 = x4>>3 ^ x3
        rrl3.b r8
        xor.b r7, r8
        ;; y5 = a5<<3 ^ a4
        rll3.b r9
        xor.b r8, r9
        mov.b r9, -3(r12)
        ;; y4 = a4>>3 ^ x2
        rrl3.b r8
        xor.b r6, r8
        mov.b r8, -4(r12)

        ;; lane p=2 = TK[16..23] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov.b @r12+, r4       ; x0
        mov.b @r12+, r5       ; x1
        mov.b @r12+, r6       ; x2
        mov.b @r12+, r7       ; x3
        mov.b @r12+, r8       ; x4
        mov.b @r12+, r9       ; x5
        mov.b @r12+, r10      ; x6
        mov.b @r12+, r11      ; x7

        ;; First, store every yj which depends on a single xi.
        mov.b r10, -7(r12)      ; x6 -> y1
        mov.b r9, -8(r12)       ; x5 -> y0

        ;; x5 is only needed for y3 (<<2) and a5 (<<3).
        ;; y3 = x5<<2 ^ x0
        rll2.b r9
        xor.b r9, r4
        mov.b r4, -5(r12)

        ;; Clobber x5 with a5 = x5<<3 ^ x4
        rla.b r9
        xor.b r8, r9
        ;; y7 = a5
        mov.b r9, -1(r12)

        ;; a5 is only needed for y2 (<<2) and b5 (<<3).
        ;; y2 = a5<<2 ^ x7
        rll2.b r9
        xor.b r9, r11
        mov.b r11, -6(r12)

        ;; a5 is now only used for b5 = a5<<3 ^ a4.

        ;; First, compute a4 = x4>>3 ^ x3. Since none of x3 and x4
        ;; are used anywhere else, clobber x4 with a4.
        rrl3.b r8
        xor.b r7, r8

        ;; Clobber a5 with b5 = a5<<3 ^ a4
        rla.b r9
        xor.b r8, r9

        ;; y6 = b5
        mov.b r9, -2(r12)

        ;; Clobber a4 with b4 = a4>>3 ^ x2
        rrl3.b r8
        xor.b r6, r8

        ;; y5 = b5<<3 ^ b4
        rll3.b r9
        xor.b r8, r9
        mov.b r9, -3(r12)

        ;; y4 = b4>>3 ^ x6<<2 ^ x1
        rrl3.b r8
        rll2.b r10
        xor.b r10, r8
        xor.b r5, r8
        mov.b r8, -4(r12)

        ;; lane p=3 = TK[24..31] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov.b @r12+, r4       ; x0
        mov.b @r12+, r5       ; x1
        mov.b @r12+, r6       ; x2
        mov.b @r12+, r7       ; x3
        mov.b @r12+, r8       ; x4
        mov.b @r12+, r9       ; x5
        mov.b @r12+, r10      ; x6
        mov.b @r12+, r11      ; x7

        ;; First, store every yj which depends on a single xi.

        mov.b r9, -7(r12)       ; x5 -> y1

        ;; calculate x[5]<<2 ^ x[0] 
        rll2.b r9
        xor.b r9,r4

        ;; calculate  a5
        rla.b r9
        xor.b r8,r9  ;;r9=a5

        ;; calculate a4
        rrl3.b r8
        xor.b r8, r7 ;;r7=a4

        ;;store y0 and y3
        mov.b r9,-8(r12)
        rll2.b r9
        xor.b r9, r11
        mov.b r11,-5(r12)

        ;;calculate b5
        rla.b r9
        xor.b r7,r9 ;;r9 =b5

        ;;calculate b4 
        rrl3.b r7
        xor.b r6,r7 ;;r7=b4

        ;;store y7
        mov.b r9, -1(r12)

        ;;store y2
        mov.b r10,r8
        rll2.b r9
        xor.b r9,r8
        mov.b r8,-6(r12)

        ;;calculate c5
        rla.b r9
        xor.b r7,r9 ;;r9=c5

        ;;calcultate c4
        rrl3.b r7
        rll2.b r10
        xor.b r10,r7
        xor.b r5,r7

        ;;store y6
        mov.b r9,-2(r12)

        ;;store y5
        rll3.b r9
        xor.b r7,r9
        mov.b r9,-3(r12)

        ;;store y4
        rrl3.b r7
        xor.b r4,r7
        mov.b r7,-4(r12)



#if LANES_NB >= 5
        ;; lane p=4 = TK[32..39] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov.b @r12+, r4       ; x0
        mov.b @r12+, r5       ; x1
        mov.b @r12+, r6       ; x2
        mov.b @r12+, r7       ; x3
        mov.b @r12+, r8       ; x4
        mov.b @r12+, r9       ; x5
        mov.b @r12+, r10      ; x6
        mov.b @r12+, r11      ; x7

        ;; First, store every yj which depends on a single xi.
        mov.b r5, -8(r12)       ; x1 -> y0
        mov.b r6, -7(r12)       ; x2 -> y1
        mov.b r8, -5(r12)       ; x4 -> y3
        mov.b r11, -2(r12)      ; x7 -> y6
        mov.b r4, -1(r12)       ; x0 -> y7

        ;; y2 = x3 ^ x4>>3
        rrl3.b r8
        xor.b r7, r8
        mov.b r8, -6(r12)

        ;; y5 = x3<<2 ^ x6
        rll2.b r7
        xor.b r10, r7
        mov.b r7, -3(r12)

        ;; y4 = x5 ^ x6<<3
        rll3.b r10
        xor.b r9, r10
        mov.b r10, -4(r12)

#if LANES_NB >= 6
        ;; lane p=5 = TK[40..47] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov   @r12+, r4         ; x0, x1
        mov.b @r12+, r6       ; x2
        mov.b @r12+, r7       ; x3
        mov.b @r12+, r8       ; x4
        mov.b @r12+, r9       ; x5
        mov.b @r12+, r10      ; x6
        mov.b @r12+, r11      ; x7

        ;; First, store every yj which depends on a single xi.
        mov.b r6, -8(r12)       ; x2 -> y0
        mov r4, -2(r12)         ; x0,x1 -> y6,y7

        ;; Clobber x0 with a4 = x5 ^ x6<<3
        mov.b r10, r4
        rll3.b r4
        xor.b r9, r4
        ;; y3 = a4
        mov.b r4, -5(r12)
        ;; y2 = x4 ^ a4>>3
        rrl3.b r4
        xor.b r8, r4
        mov.b r4, -6(r12)

        ;; Clobber x0 with x4>>3, since x4 is still needed for y5.
        mov.b r8, r4
        rrl3.b r4
        ;; y1 = x3 ^ x4>>3
        xor.b r7, r4
        mov.b r4, -7(r12)

        ;; y5 = x4<<2 ^ x7
        rll2.b r8
        xor.b r11, r8
        mov.b r8, -3(r12)

        ;; y4 = x3<<2 ^ x6 ^ x7<<3
        rll2.b r7
        rll3.b r11
        xor.b r7, r10
        xor.b r11, r10
        mov.b r10, -4(r12)

#if LANES_NB >= 7
        ;; lane p=6 = TK[48..55] ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov.b @r12+, r4       ; x0
        mov.b @r12+, r5       ; x1
        mov.b @r12+, r6       ; x2
        mov.b @r12+, r7       ; x3
        mov.b @r12+, r8       ; x4
        mov.b @r12+, r9       ; x5
        mov.b @r12+, r10      ; x6
        mov.b @r12+, r11      ; x7

        ;; First, store every yj which depends on a single xi.
        mov.b r5, -2(r12)       ; x1 -> y6
        mov.b r6, -1(r12)       ; x2 -> y7

        ;; Clobber x1 with y0 = x3 ^ x4>>3
        mov.b r8, r5
        rrl3.b r5
        xor.b r7, r5
        mov.b r5, -8(r12)

        ;; Clobber x1 with x6<<3, then x5 with a4 = x5 ^ x6<<3
        mov.b r10, r5
        rll3.b r5
        xor.b r5, r9

        ;; Clobber x1 with x7<<3, then x3 with b4 = x3<<2 ^ x6 ^ x7<<3
        mov.b r11, r5
        rll3.b r5
        rll2.b r7
        xor.b r5, r7
        xor.b r10, r7

        ;; y3 = b4
        mov.b r7, -5(r12)

        ;; Clobber b4 with y2 = a4 ^ b4>>3
        rrl3.b r7
        xor.b r9, r7
        mov.b r7, -6(r12)

        ;; Clobber x2 with x4<<2, x3 with x0<<3
        mov.b r8, r6
        rll2.b r6
        mov.b r4, r7
        rll3.b r7
        ;; Clobber x7 with y4 = x4<<2 ^ x7 ^ x0<<3
        xor.b r6, r11
        xor.b r7, r11
        mov.b r11, -4(r12)

        ;; Clobber x1 with a4<<2
        mov.b r9, r5
        rll2.b r5
        ;; y5 = a4<<2 ^ x0
        xor.b r5, r4
        mov.b r4, -3(r12)

        ;; y1 = x4 ^ a4>>3
        rrl3.b r9
        xor.b r9, r8
        mov.b r8, -7(r12)
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
