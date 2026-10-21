.syntax unified
.thumb
.text
.p2align 2
.global cp_result
.type cp_result,%function
.thumb_func
cp_result:
    ldrb.w r0,[sp,#0x4c]
    tst.w r0,#1
    beq failed
.global cp_success_branch
cp_success_branch:
    .hword 0xf000,0xb800 // Resolved to original accepted path 0x48c790.
failed:
    ldr r2,[sp,#0x50]
    lsrs r0,r2,#16
    movw r1,#0xc17e
    cmp r0,r1
    bne retry
.global cp_failure_branch
cp_failure_branch:
    .hword 0xf000,0xb800 // Native terminal error path 0x48c778.
retry:
.global cp_retry_branch
cp_retry_branch:
    .hword 0xf000,0xb800 // Original retry/error logging 0x48c74e.
.size cp_result, .-cp_result
