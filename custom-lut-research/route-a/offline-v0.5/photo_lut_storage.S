/* Exact-build cold-start initialization for the declared BSS extension.
 * Called after the native BSS clear and before native CPU publication.
 * r0/r1 are overwritten by the displaced/next original instructions.
 */
.syntax unified
.arm
.text
.p2align 2
.global photo_lut_storage_init
.type photo_lut_storage_init,%function
photo_lut_storage_init:
    movw r0,#0x5f5c
    movt r0,#0x1b8
    mov r1,#0x80
    str r1,[r0]
    str r1,[r0,#4]
    movw r0,#0xa000
.global photo_lut_storage_resume
photo_lut_storage_resume:
    .word 0xea000000
.size photo_lut_storage_init,.-photo_lut_storage_init
