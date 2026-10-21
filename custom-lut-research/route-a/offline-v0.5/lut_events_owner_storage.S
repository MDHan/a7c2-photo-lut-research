.text
.global lh_owner_context
lh_owner_context:
.global lh_owner_state_page
lh_owner_state_page:
    nop
.global lh_owner_state_offset
lh_owner_state_offset:
    nop
    ret
.global lh_monotonic
lh_monotonic:
    mov x1,x0
    mov x0,#1
    mov x8,#113
    svc #0
    ret

.global lh_copy_original
lh_copy_original:
.global lh_copy_displaced
lh_copy_displaced:
    nop
.global lh_copy_resume
lh_copy_resume:
    nop

.global lh_delete_original
lh_delete_original:
    .word 0xa9bc7bfd
.global lh_delete_resume
lh_delete_resume:
    nop

.global lh_delete_cube_original
lh_delete_cube_original:
    .word 0xa9bc7bfd
.global lh_delete_cube_resume
lh_delete_cube_resume:
    nop

.global lh_reset_original
lh_reset_original:
    .word 0xa9b87bfd
.global lh_reset_resume
lh_reset_resume:
    nop
