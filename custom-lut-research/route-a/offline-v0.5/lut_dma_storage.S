/* Cold-only second stage, reached after the native RO tail gains execution.
 * r0-r3 are dead at the resumed native initialization point. No stack/calls.
 */
#ifndef LUT_DMA_WORDS
#include "lifecycle-dev/dma-placement-build/layout.h"
#endif
.syntax unified
.arm
.text
.p2align 2
.global dma_storage_copy
.type dma_storage_copy,%function
dma_storage_copy:
    movw r0,#0x9aa0
    movt r0,#0x120
    movw r1,#0x6000
    movt r1,#0x1b8
    movw r2,#LUT_DMA_WORDS
1:
    ldr r3,[r0],#4
    str r3,[r1]
    bic r3,r1,#31
.global dma_clean_code_line
dma_clean_code_line:
    mcr p15,0,r3,c7,c10,1
    add r1,r1,#4
    subs r2,r2,#1
    bne 1b
    dsb sy
    /* L1[0x1b] then L2[0x86], for new reserved page 0x1b86000. */
    movw r0,#0x806c
    movt r0,#0x1b8
    ldr r0,[r0]
    bfc r0,#0,#10
    add r0,r0,#0x218
    ldr r1,[r0]
    bic r1,r1,#1
    orr r1,r1,#0x220
.global dma_storage_pte
dma_storage_pte:
    str r1,[r0]
    bic r0,r0,#31
.global dma_clean_table_line
dma_clean_table_line:
    mcr p15,0,r0,c7,c10,1
    dsb sy
    mov r0,#0
.global dma_invalidate_tlb
dma_invalidate_tlb:
    mcr p15,0,r0,c8,c3,0
.global dma_invalidate_icache
dma_invalidate_icache:
    mcr p15,0,r0,c7,c1,0
.global dma_invalidate_predictor
dma_invalidate_predictor:
    mcr p15,0,r0,c7,c1,6
    dsb sy
    isb sy
    movw r0,#0xa000
.global dma_storage_resume
dma_storage_resume:
    .word 0xea000000
.size dma_storage_copy,.-dma_storage_copy
