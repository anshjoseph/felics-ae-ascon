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
	mov.b 10(r12), r6
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
