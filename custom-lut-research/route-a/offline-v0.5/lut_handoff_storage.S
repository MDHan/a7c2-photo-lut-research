/* Exact-build cold initialization, after native BSS clear, before SEV.
 * Only the last native RO-data page gains execution; write/cache attributes
 * stay unchanged. CP15 operations are privileged cold-start operations.
 */
.syntax unified
.arm
.text
.p2align 2
.global handoff_storage_init
.type handoff_storage_init,%function
handoff_storage_init:
    movw r0,#0x5f5c
    movt r0,#0x1b8
    mov r1,#0x80
    str r1,[r0]
    str r1,[r0,#4]
    /* L1[0x10], then L2[0xc6], for virtual page 0x010c6000. */
    movw r0,#0x8040
    movt r0,#0x1b8
    ldr r0,[r0]
    bfc r0,#0,#10
    add r0,r0,#0x318
    ldr r1,[r0]
    bic r1,r1,#1
.global handoff_pte_store
handoff_pte_store:
    str r1,[r0]
    bic r0,r0,#31
.global handoff_clean_table_line
handoff_clean_table_line:
    mcr p15,0,r0,c7,c10,1
    dsb sy
    mov r0,#0
.global handoff_invalidate_tlb
handoff_invalidate_tlb:
    mcr p15,0,r0,c8,c3,0
.global handoff_invalidate_icache
handoff_invalidate_icache:
    mcr p15,0,r0,c7,c1,0
.global handoff_invalidate_predictor
handoff_invalidate_predictor:
    mcr p15,0,r0,c7,c1,6
    dsb sy
    isb sy
    movw r0,#0xa000
.global handoff_storage_resume
handoff_storage_resume:
    .word 0xea000000
.size handoff_storage_init,.-handoff_storage_init
