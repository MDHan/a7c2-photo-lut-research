.text
.p2align 2
.global ap_entry
.type ap_entry, %function
ap_entry:
    cbnz w6, native_entry
    sub w16, w0, #3
    cmp w16, #15
    b.hi native_entry
    cmp w1, #1
    b.ne native_entry
    cbnz w2, native_entry
    cmp w7, #1
    b.ne native_entry
    sub w16, w5, #12
    cmp w16, #3
    b.hi native_entry
    mov w6, #1
native_entry:
    stp x29, x30, [sp, #-0x50]!
.global ap_resume
ap_resume:
    .inst 0x14000000 // Builder resolves a PC-relative branch to 0x352c5e0.
.size ap_entry, .-ap_entry
