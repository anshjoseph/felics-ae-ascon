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

;; This file provides the implementation for Lilliput-TBC.

#include "felics/helpers.S"

#include "parameters.h"
/* Only ΘCB3 mode needs decryption functions: define a symbol to
 * selectively hide them. */
#if TWEAK_LENGTH_BITS == 192
#define LILLIPUT_I
#endif

rodata S
        .byte \
        0x20, 0x00, 0xB2, 0x85, 0x3B, 0x35, 0xA6, 0xA4, 0x30, 0xE4, 0x6A, 0x2C, 0xFF, 0x59, 0xE2, 0x0E, \
        0xF8, 0x1E, 0x7A, 0x80, 0x15, 0xBD, 0x3E, 0xB1, 0xE8, 0xF3, 0xA2, 0xC2, 0xDA, 0x51, 0x2A, 0x10, \
        0x21, 0x01, 0x23, 0x78, 0x5C, 0x24, 0x27, 0xB5, 0x37, 0xC7, 0x2B, 0x1F, 0xAE, 0x0A, 0x77, 0x5F, \
        0x6F, 0x09, 0x9D, 0x81, 0x04, 0x5A, 0x29, 0xDC, 0x39, 0x9C, 0x05, 0x57, 0x97, 0x74, 0x79, 0x17, \
        0x44, 0xC6, 0xE6, 0xE9, 0xDD, 0x41, 0xF2, 0x8A, 0x54, 0xCA, 0x6E, 0x4A, 0xE1, 0xAD, 0xB6, 0x88, \
        0x1C, 0x98, 0x7E, 0xCE, 0x63, 0x49, 0x3A, 0x5D, 0x0C, 0xEF, 0xF6, 0x34, 0x56, 0x25, 0x2E, 0xD6, \
        0x67, 0x75, 0x55, 0x76, 0xB8, 0xD2, 0x61, 0xD9, 0x71, 0x8B, 0xCD, 0x0B, 0x72, 0x6C, 0x31, 0x4B, \
        0x69, 0xFD, 0x7B, 0x6D, 0x60, 0x3C, 0x2F, 0x62, 0x3F, 0x22, 0x73, 0x13, 0xC9, 0x82, 0x7F, 0x53, \
        0x32, 0x12, 0xA0, 0x7C, 0x02, 0x87, 0x84, 0x86, 0x93, 0x4E, 0x68, 0x46, 0x8D, 0xC3, 0xDB, 0xEC, \
        0x9B, 0xB7, 0x89, 0x92, 0xA7, 0xBE, 0x3D, 0xD8, 0xEA, 0x50, 0x91, 0xF1, 0x33, 0x38, 0xE0, 0xA9, \
        0xA3, 0x83, 0xA1, 0x1B, 0xCF, 0x06, 0x95, 0x07, 0x9E, 0xED, 0xB9, 0xF5, 0x4C, 0xC0, 0xF4, 0x2D, \
        0x16, 0xFA, 0xB4, 0x03, 0x26, 0xB3, 0x90, 0x4F, 0xAB, 0x65, 0xFC, 0xFE, 0x14, 0xF7, 0xE3, 0x94, \
        0xEE, 0xAC, 0x8C, 0x1A, 0xDE, 0xCB, 0x28, 0x40, 0x7D, 0xC8, 0xC4, 0x48, 0x6B, 0xDF, 0xA5, 0x52, \
        0xE5, 0xFB, 0xD7, 0x64, 0xF9, 0xF0, 0xD3, 0x5E, 0x66, 0x96, 0x8F, 0x1D, 0x45, 0x36, 0xCC, 0xC5, \
        0x4D, 0x9F, 0xBF, 0x0F, 0xD1, 0x08, 0xEB, 0x43, 0x42, 0x19, 0xE7, 0x99, 0xA8, 0x8E, 0x58, 0xC1, \
        0x9A, 0xD4, 0x18, 0x47, 0xAA, 0xAF, 0xBC, 0x5B, 0xD5, 0x11, 0xD0, 0xB0, 0x70, 0xBB, 0x0D, 0xBA


function nonlinear_and_linear
        ;; r12: X
        ;; r13: RTK

        ;; Cf. figure 2.8 in the specification:
        ;;
        ;; - x7 is the "universal donor", XORed to x15 to x9
        ;;   (directly) and to x8 (after going through the S-box).
        ;;
        ;; - x15 is the "universal recipient", XORed to x1 to x7
        ;;   (directly) and to x0 (after going through the S-box).
        ;;
        ;; Dedicate r7 and r8 to x7 and x15.  Note that to compute
        ;;
        ;;      x15 = x15 xor LOTS OF THINGS
        ;;
        ;; We first set r8 to LOTS OF THINGS, *then* XOR it back to
        ;; 15(r12).  No need to load 15(r12) at all.
        ;;
        ;; r9 is our iterator.  For j in [1, 6], we:
        ;;
        ;; - load xj into r9,
        ;; - *first* XOR r9 to r8 (linear layer)
        ;; - *then* do the non-linear layer:
        ;;      - r9 = S(r9 xor RTK[j])
        ;;      - X[15-j] = X[15-j] xor r9
        ;;
        ;; Special cases:
        ;;
        ;; - j=0 ==> use the result of the non-linear layer to
        ;;           initialize r8 (future x15).
        ;;
        ;; - j=7 ==> x7 is already cached in r7.

        push r7                 ; x7
        push r8                 ; x15
        push r9                 ; xj / x{15-j}

        mov.b 7(r12), r7

        mov.b @r12+, r8
        xor.b @r13+, r8
        mov.b S(r8), r8

        mov.b @r12+, r9
        xor.b r9, r8
        xor.b @r13+, r9
        mov.b S(r9), r9
        xor.b r7, r9
        xor.b r9, 12(r12)

        mov.b @r12+, r9
        xor.b r9, r8
        xor.b @r13+, r9
        mov.b S(r9), r9
        xor.b r7, r9
        xor.b r9, 10(r12)

        mov.b @r12+, r9
        xor.b r9, r8
        xor.b @r13+, r9
        mov.b S(r9), r9
        xor.b r7, r9
        xor.b r9, 8(r12)

        mov.b @r12+, r9
        xor.b r9, r8
        xor.b @r13+, r9
        mov.b S(r9), r9
        xor.b r7, r9
        xor.b r9, 6(r12)

        mov.b @r12+, r9
        xor.b r9, r8
        xor.b @r13+, r9
        mov.b S(r9), r9
        xor.b r7, r9
        xor.b r9, 4(r12)

        mov.b @r12+, r9
        xor.b r9, r8
        xor.b @r13+, r9
        mov.b S(r9), r9
        xor.b r7, r9
        xor.b r9, 2(r12)

        mov.b r7, r9
        xor.b r9, r8
        xor.b @r13, r9
        mov.b S(r9), r9
        xor.b r9, 1(r12)

        xor.b r8, 8(r12)
        

        pop r9
        pop r8
        pop r7
        ret

;; Permutations:
;;
;; Perform permutations "in-place", i.e. without memcpy, by:
;;
;; 1. Saving X[0..7] to registers,
;; 2. Setting X[j] = X[PI[j]] for j in [8, 15],
;; 3. Setting X[j] = corresponding register for j in [0, 7].
;;
;; When possible, move words instead of bytes.

function permutation_enc
        ;; r12: X
        push r4
        push r5
        push r6
        push r7
        push r8
        push r9
        push r10

        mov.b @r12+,r4   ; save X[0]
        mov.b @r12+,r5   ; save X[1]
        mov.b @r12+,r6   ; save X[2]
        mov.b @r12+,r7   ; save X[3]
        mov   @r12+,r8   ; save X[4-5]
        mov.b @r12+,r9   ; save X[6]
        mov.b @r12+,r10  ; save X[7]

        mov   @r12+, -5(r12)    ; X[8-9] -> X[4-5]
        mov.b @r12+, -8(r12)    ; X[10] -> X[3]
        mov.b @r12+, -11(r12)   ; X[11] -> X[1]
        mov.b @r12+, -11(r12)   ; X[12] -> X[2]
        mov.b @r12+, -8(r12)    ; X[13] -> X[6]
        mov.b @r12+, -15(r12)   ; X[14] -> X[0]
        mov.b @r12+,- 9(r12)    ; X[15] -> X[7]

        mov.b r4, -3(r12)       ; X[0] -> X[13]
        mov.b r5, -7(r12)       ; X[1] -> X[9]
        mov.b r6, -2(r12)       ; X[2] -> X[14]
        mov.b r7, -8(r12)       ; X[3] -> X[8]
        mov   r8, -6(r12)       ; X[4-5] -> X[10-11]
        mov.b r9, -4(r12)       ; X[6] -> X[12]
        mov.b r10,-1(r12)       ; X[7] -> X[15]

        pop r10
        pop r9
        pop r8
        pop r7
        pop r6
        pop r5
        pop r4

        ret

#ifdef LILLIPUT_I

function permutation_dec
        ;; r12: X
        push r4
        push r5
        push r6
        push r7
        push r8
        push r9
        push r10

        mov.b @r12+, r4         ; save X[0]
        mov.b @r12+, r5         ; save X[1]
        mov.b @r12+, r6         ; save X[2]
        mov.b @r12+, r7         ; save X[3]
        mov   @r12+, r8         ; save X[4-5]
        mov.b @r12+, r9         ; save X[6]
        mov.b @r12+, r10        ; save X[7]

        mov.b @r12+, -6(r12)    ; X[8] -> X[3]
        mov.b @r12+, -9(r12)    ; X[9] -> X[1]
        mov   @r12+, -7(r12)    ; X[10-11] -> X[4-5]
        mov.b @r12+, -7(r12)    ; X[12] -> X[6]
        mov.b @r12+, -14(r12)   ; X[13] -> X[0]
        mov.b @r12+, -13(r12)   ; X[14] -> X[2]
        mov.b @r12+, -9(r12)    ; X[15] -> X[7]

        mov.b r4 , -2(r12)      ; X[0] -> X[14]
        mov.b r5 , -5(r12)      ; X[1] -> X[11]
        mov.b r6 , -4(r12)      ; X[2] -> X[12]
        mov.b r7 , -6(r12)      ; X[3] -> X[10]
        mov   r8 , -8(r12)      ; X[4-5] -> X[8-9]
        mov.b r9 , -3(r12)      ; X[6] -> X[13]
        mov.b r10, -1(r12)      ; X[7] -> X[15]

        pop r10
        pop r9
        pop r8
        pop r7
        pop r6
        pop r5
        pop r4

        ret

#endif
