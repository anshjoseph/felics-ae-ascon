 
;; Permutations:
;;
;; Perform permutations "in-place", i.e. without memcpy, by:
;;
;; 1. Saving X[0..7] to registers,
;; 2. Setting X[j] = X[PI[j]] for j in [8, 15],
;; 3. Setting X[j] = corresponding register for j in [0, 7].
;;
;; When possible, move words instead of bytes.

        .global permutation_enc
        .type permutation_enc, @function
permutation_enc:
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

        mov   @r12+, -5(r12)    ; X[8] -> X[4-5]
        mov.b @r12+, -8(r12)    ; X[9-10] -> X[3]
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

        .global permutation_dec
        .type permutation_dec, @function
permutation_dec:
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