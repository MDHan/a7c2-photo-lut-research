/* Tracked photo callbacks. Builder binds declared BSS cells and recorder.
 * Experimental integration; not yet installed in a flash-ready candidate. */
.syntax unified
.thumb
.text
.p2align 2
.macro WRAPPER name, cell, resume
.global \name
.type \name,%function
.thumb_func
\name:
    push {r0-r4,lr}
    mov r4,r0
    mov r1,r3
    ldr r0,\cell
    mov r3,r4
    ldr r4,.Lrecord
    blx r4
    cmp r0,#0
    beq .Ldrop\@
    pop.w {r0-r4,lr}
.global \resume
\resume:
    .hword 0xf000,0xb800
.Ldrop\@:
    pop {r0-r4,pc}
.size \name,.-\name
.endm
WRAPPER photo_context0, .Lcell0, callback0_resume
WRAPPER photo_context1, .Lcell1, callback1_resume
.p2align 2
.global cell0_address, cell1_address, record_address
cell0_address:
.Lcell0: .word 0
cell1_address:
.Lcell1: .word 0
record_address:
.Lrecord: .word 0
