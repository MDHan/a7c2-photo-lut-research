/* Experimental callback-tag transport. Not applied to a candidate image.
 * Capture the registration word with the callback pointer under native lock;
 * pass it as the fourth argument after the native slot has been removed.
 */
.syntax unified
.thumb
.text
.p2align 2
.global vfx_tag_capture
.type vfx_tag_capture,%function
.thumb_func
vfx_tag_capture:
    ldr.w r8,[sb,#8]
    ldr.w fp,[sb,#4]
.global vfx_tag_capture_resume
vfx_tag_capture_resume:
    .hword 0xf000,0xb800
.size vfx_tag_capture, .-vfx_tag_capture
.p2align 2
.global vfx_tag_deliver
.type vfx_tag_deliver,%function
.thumb_func
vfx_tag_deliver:
    ldr.w r1,[r0,r4,lsl #3]
    movs r0,#0
    mov r3,fp
    blx r8
.global vfx_tag_deliver_resume
vfx_tag_deliver_resume:
    .hword 0xf000,0xb800
.size vfx_tag_deliver, .-vfx_tag_deliver
