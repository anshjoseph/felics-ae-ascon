.macro rodata c
        .section .rodata.\c
        \c:
.endm

.macro function f
        .section .text.\f
        .global \f
        .type \f, @function
        \f:
.endm
