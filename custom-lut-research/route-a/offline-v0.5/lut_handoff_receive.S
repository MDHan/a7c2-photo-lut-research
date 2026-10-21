.text
.global lh_receive_bridge
lh_receive_bridge:
    sub sp,sp,#704
    stp x0,x1,[sp,#0]
    stp x2,x3,[sp,#16]
    stp x4,x5,[sp,#32]
    stp x6,x7,[sp,#48]
    stp x8,x9,[sp,#64]
    stp x10,x11,[sp,#80]
    stp x12,x13,[sp,#96]
    stp x14,x15,[sp,#112]
    stp x16,x17,[sp,#128]
    stp x18,x30,[sp,#144]
    mrs x0,nzcv
    str x0,[sp,#160]
    mrs x0,fpcr
    mrs x1,fpsr
    stp x0,x1,[sp,#176]
    stp q0,q1,[sp,#192]
    stp q2,q3,[sp,#224]
    stp q4,q5,[sp,#256]
    stp q6,q7,[sp,#288]
    stp q8,q9,[sp,#320]
    stp q10,q11,[sp,#352]
    stp q12,q13,[sp,#384]
    stp q14,q15,[sp,#416]
    stp q16,q17,[sp,#448]
    stp q18,q19,[sp,#480]
    stp q20,q21,[sp,#512]
    stp q22,q23,[sp,#544]
    stp q24,q25,[sp,#576]
    stp q26,q27,[sp,#608]
    stp q28,q29,[sp,#640]
    stp q30,q31,[sp,#672]
    mov x0,x19
.global lh_receive_length_call
lh_receive_length_call:
    nop
    mov w2,w0
    mov x1,x19
.global lh_receive_state_page
lh_receive_state_page:
    nop
.global lh_receive_state_offset
lh_receive_state_offset:
    nop
.global lh_receive_core_call
lh_receive_core_call:
    nop
    cbnz w0,lh_owned
.macro restore
    ldp q0,q1,[sp,#192]
    ldp q2,q3,[sp,#224]
    ldp q4,q5,[sp,#256]
    ldp q6,q7,[sp,#288]
    ldp q8,q9,[sp,#320]
    ldp q10,q11,[sp,#352]
    ldp q12,q13,[sp,#384]
    ldp q14,q15,[sp,#416]
    ldp q16,q17,[sp,#448]
    ldp q18,q19,[sp,#480]
    ldp q20,q21,[sp,#512]
    ldp q22,q23,[sp,#544]
    ldp q24,q25,[sp,#576]
    ldp q26,q27,[sp,#608]
    ldp q28,q29,[sp,#640]
    ldp q30,q31,[sp,#672]
    ldp x0,x1,[sp,#176]
    msr fpcr,x0
    msr fpsr,x1
    ldr x0,[sp,#160]
    msr nzcv,x0
    ldp x0,x1,[sp,#0]
    ldp x2,x3,[sp,#16]
    ldp x4,x5,[sp,#32]
    ldp x6,x7,[sp,#48]
    ldp x8,x9,[sp,#64]
    ldp x10,x11,[sp,#80]
    ldp x12,x13,[sp,#96]
    ldp x14,x15,[sp,#112]
    ldp x16,x17,[sp,#128]
    ldp x18,x30,[sp,#144]
    add sp,sp,#704
.endm
    restore
    ldrb w0,[x19]
.global lh_receive_resume
lh_receive_resume:
    nop
lh_owned:
    restore
.global lh_receive_consumed
lh_receive_consumed:
    nop
