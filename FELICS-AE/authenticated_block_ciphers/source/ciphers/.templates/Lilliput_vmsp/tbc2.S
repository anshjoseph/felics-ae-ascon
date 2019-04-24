.section .text
.globl nonlinear_and_linear
.type nonlinear_and_linear, @function
.globl permutation_enc
.type permutation_enc, @function
.globl permutation_dec
.type permutation_dec, @function

nonlinear_and_linear:
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
        ;;   initialize x15.
        ;;
        ;; - j=7 ==> x7 is already cached in r7.

	push r7                 ; x7
        push r8                 ; x15
        push r9                 ; xj / x{15-j}

        mov.b 7(r12), r7
        clr r8

        mov.b 0(r12), r9
        xor.b 0(r13), r9
        mov.b S(r9), r9
        mov.b r9, r8

        mov.b 1(r12), r9
        xor.b r9, r8
        xor.b 1(r13), r9
        mov.b S(r9), r9
        xor.b r7, r9
        xor.b r9, 14(r12)

        mov.b 2(r12), r9
        xor.b r9, r8
        xor.b 2(r13), r9
        mov.b S(r9), r9
        xor.b r7, r9
        xor.b r9, 13(r12)

        mov.b 3(r12), r9
        xor.b r9, r8
        xor.b 3(r13), r9
        mov.b S(r9), r9
        xor.b r7, r9
        xor.b r9, 12(r12)

        mov.b 4(r12), r9
        xor.b r9, r8
        xor.b 4(r13), r9
        mov.b S(r9), r9
        xor.b r7, r9
        xor.b r9, 11(r12)

        mov.b 5(r12), r9
        xor.b r9, r8
        xor.b 5(r13), r9
        mov.b S(r9), r9
        xor.b r7, r9
        xor.b r9, 10(r12)

        mov.b 6(r12), r9
        xor.b r9, r8
        xor.b 6(r13), r9
        mov.b S(r9), r9
        xor.b r7, r9
        xor.b r9, 9(r12)

        mov.b r7, r9
        xor.b r9, r8
        xor.b 7(r13), r9
        mov.b S(r9), r9
        xor.b r9, 8(r12)

        xor.b r8, 15(r12)

        pop r9
	pop r8
        pop r7
        ret

permutation_enc:
        ;; r12: X
	push r4
	push r6
	push r7
	push r8
	push r9
	push r10
	push r11

	mov 8(r12), r4
	mov.b 10(r12), r6
	mov.b 11(r12), r7
	mov.b 12(r12), r8
	mov.b 13(r12), r9
	mov.b 14(r12), r10
	mov.b 15(r12), r11

	mov.b 0(r12), 13(r12)
	mov.b 1(r12), 9(r12)
	mov.b 2(r12), 14(r12)
	mov.b 3(r12), 8(r12)
	mov 4(r12), 10(r12)
	mov.b 6(r12), 12(r12)
	mov.b 7(r12), 15(r12)
	
	mov r4, 4(r12)
	mov.b r6, 3(r12)
	mov.b r7, 1(r12)
	mov.b r8, 2(r12)
	mov.b r9, 6(r12)
	mov.b r10, 0(r12)
	mov.b r11, 7(r12)

        pop r11
	pop r10
	pop r9
	pop r8
	pop r7
	pop r6
	pop r4

        ret

permutation_dec:
        ;; r12: X
        push r4
	push r5
	push r6
	push r8
	push r9
	push r10
	push r11

	mov.b 8(r12), r4
	mov.b 9(r12), r5
	mov 10(r12), r6
	mov.b 12(r12), r8
	mov.b 13(r12), r9
	mov.b 14(r12), r10
	mov.b 15(r12), r11

	mov.b 0(r12), 14(r12)
	mov.b 1(r12), 11(r12)
	mov.b 2(r12), 12(r12)
	mov.b 3(r12), 10(r12)
	mov 4(r12), 8(r12)
	mov.b 6(r12), 13(r12)
	mov.b 7(r12), 15(r12)

	mov.b r4, 3(r12)
	mov.b r5, 1(r12)
	mov r6, 4(r12)
	mov.b r8, 6(r12)
	mov.b r9, 0(r12)
	mov.b r10, 2(r12)
	mov.b r11, 7(r12)
        
	pop r11
	pop r10
	pop r9
	pop r8
	pop r6
	pop r5
	pop r4

        ret
