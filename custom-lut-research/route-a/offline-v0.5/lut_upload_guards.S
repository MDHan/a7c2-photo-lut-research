/* Exact-build AP guards. All external branches/ADRP instructions are resolved
 * by build_upload_guards.py. No absolute runtime pointers or new global state.
 */
.text
.p2align 2
.global lut_read_size_guard
.global lut_special_buffer_page
.global lut_regular_buffer_page
.global lut_read_size_resume
lut_read_size_guard:
    tst w0, #0xff
    b.eq size_done
    ldr w9, [x20]             // actual fread count in native result
    ldr x10, [x20, #8]        // selected native static buffer
lut_special_buffer_page:
    .inst 0x9000000b          // adrp x11, GOT page; builder resolves
    ldr x11, [x11, #0x8f8]
    cmp x10, x11
    b.ne regular_buffer
    mov w10, #48124          // 48000 LUT + 124 ArtGen bytes
    b check_size
regular_buffer:
lut_regular_buffer_page:
    .inst 0x9000000b
    ldr x11, [x11, #0x438]
    cmp x10, x11
    b.ne invalid_size
    mov w10, #48000
check_size:
    cmp w9, w10
    b.hs size_done
invalid_size:
    mov w0, #0               // native caller leaves both outputs zero
size_done:
    tst w0, #0xff            // displaced instruction, preserve branch flags
lut_read_size_resume:
    b .

.p2align 2
.global lut_checked_mapping
.global lut_native_map_call
.global lut_failed_map_close
lut_checked_mapping:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x19, [sp, #16]
    mov x19, x1             // native mapping result struct
lut_native_map_call:
    bl .                    // original 34d37e8 wrapper, executes once
    ldr w9, [x19, #32]
    cbnz w9, mapping_done   // existing open failure remains unchanged
    ldr x9, [x19, #16]      // raw mmap result, before page offset addition
    cmn x9, #1
    b.ne mapping_done
    ldr w0, [x19, #12]
lut_failed_map_close:
    bl .                    // close the opened /dev/mem fd, no munmap(-1)
    stp xzr, xzr, [x19]
    stp xzr, xzr, [x19, #16]
    mov w9, #-1
    str w9, [x19, #12]
    mov w9, #2
    str w9, [x19, #32]      // existing caller's native error branch
mapping_done:
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
