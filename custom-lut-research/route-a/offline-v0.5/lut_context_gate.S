/* Native 0x303de48 is used by the LUT selection/upload constructors.
 * Enable REC_STILL only for PPLUT1..4, Log off, non-cinematic mode.
 * Other system states execute the displaced comparison and original body.
 * The builder resolves the resume branch; no absolute runtime addresses.
 */
.text
.p2align 2
.global lut_context_gate
.global lut_context_resume
lut_context_gate:
    cmp w0, #2
    b.ne original
    cbnz w1, reject
    sub w9, w2, #12
    cmp w9, #3
    b.hi reject
    cmp w3, #1
    cset w0, eq
    ret
reject:
    mov w0, #0
    ret
original:
    cmp w0, #3
lut_context_resume:
    b .
