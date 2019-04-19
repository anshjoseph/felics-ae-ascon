.section .text
.globl nonlinear
.type nonlinear, @function
.globl permutation_enc
.type permutation_enc, @function
.globl permutation_dec
.type permutation_dec, @function

nonlinear:
        push r8
        push r9

        mov.b 0(r13), r8
        mov.b 0(r12), r9
        xor.b r8, r9
        mov.b S(r9), r9
        xor.b r9, 15(r12)

        mov.b 1(r13), r8
        mov.b 1(r12), r9
        xor.b r8, r9
        mov.b S(r9), r9
        xor.b r9, 14(r12)

        mov.b 2(r13), r8
        mov.b 2(r12), r9
        xor.b r8, r9
        mov.b S(r9), r9
        xor.b r9, 13(r12)

        mov.b 3(r13), r8
        mov.b 3(r12), r9
        xor.b r8, r9
        mov.b S(r9), r9
        xor.b r9, 12(r12)

        mov.b 4(r13), r8
        mov.b 4(r12), r9
        xor.b r8, r9
        mov.b S(r9), r9
        xor.b r9, 11(r12)

        mov.b 5(r13), r8
        mov.b 5(r12), r9
        xor.b r8, r9
        mov.b S(r9), r9
        xor.b r9, 10(r12)

        mov.b 6(r13), r8
        mov.b 6(r12), r9
        xor.b r8, r9
        mov.b S(r9), r9
        xor.b r9, 9(r12)

        mov.b 7(r13), r8
        mov.b 7(r12), r9
        xor.b r8, r9
        mov.b S(r9), r9
        xor.b r9, 8(r12)

        pop r9
        pop r8
        ret

permutation_enc:
        ;; r12: old X
        ;; r13: new X
	mov.b 0(r12), 13(r13)
	mov.b 1(r12), 9(r13)
	mov.b 2(r12), 14(r13)
	mov.b 3(r12), 8(r13)
	mov.b 4(r12), 10(r13)
	mov.b 5(r12), 11(r13)
	mov.b 6(r12), 12(r13)
	mov.b 7(r12), 15(r13)
	mov.b 8(r12), 4(r13)
	mov.b 9(r12), 5(r13)
	mov.b 10(r12), 3(r13)
	mov.b 11(r12), 1(r13)
	mov.b 12(r12), 2(r13)
	mov.b 13(r12), 6(r13)
	mov.b 14(r12), 0(r13)
	mov.b 15(r12), 7(r13)
        ret

permutation_dec:
        ;; r12: old X
        ;; r13: new X
	mov.b 0(r12), 14(r13)
	mov.b 1(r12), 11(r13)
	mov.b 2(r12), 12(r13)
	mov.b 3(r12), 10(r13)
	mov.b 4(r12), 8(r13)
	mov.b 5(r12), 9(r13)
	mov.b 6(r12), 13(r13)
	mov.b 7(r12), 15(r13)
	mov.b 8(r12), 3(r13)
	mov.b 9(r12), 1(r13)
	mov.b 10(r12), 4(r13)
	mov.b 11(r12), 5(r13)
	mov.b 12(r12), 6(r13)
	mov.b 13(r12), 0(r13)
	mov.b 14(r12), 2(r13)
	mov.b 15(r12), 7(r13)
        ret
