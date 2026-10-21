/* Preserve native inactivity retry state when bb30ce fails.
 * Does not cancel, drain, acquire or free any photo lifecycle cell.
 */
.syntax unified
.thumb
.text
.p2align 2
.global lut_idle_release_result
.type lut_idle_release_result,%function
.thumb_func
lut_idle_release_result:
    cmp r0,#0
    ite eq
    moveq r0,#2
    movne r0,#1
.global lut_idle_release_resume
lut_idle_release_resume:
    .hword 0xf000,0xb800
.size lut_idle_release_result,.-lut_idle_release_result
