.section .text
.globl nonlinear
.type nonlinear, @function

nonlinear:
	push r4
	push r7
	push r8
	push r9
	push r10
	mov r13, r4
	add #8, r4
	mov r12, r7
	add #15, r7
loopstart:
	mov.b @r13+, r8
	mov.b @r12+, r9
	xor.b r8, r9
	mov.b S(r9), r9
	mov.b @r7, r10
	xor.b r9, r10
	mov.b r10, @r7
	dec r7
	cmp r4, r13
	jnz loopstart
	pop r10
	pop r9
	pop r8
	pop r7
	pop r4
        ret
