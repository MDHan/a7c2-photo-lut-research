.syntax unified
.thumb
.text
.align 2
.macro original name, bits, resume
.global lut_original_\name
.thumb_func
lut_original_\name:
.inst.n 0xb5f0
.inst.n 0xaf03
.inst.w \bits
ldr.w pc,[pc,#0]
.word \resume
.endm
original apply,0xe92d0f00,0x4e8775
original load,0xe92d0f00,0x54e165
original art,0xe92d0f00,0x54e3a1
.global lut_original_queue
.thumb_func
lut_original_queue:
.inst.n 0xb5f0
.inst.n 0xaf03
.inst.w 0xe92d0700
.inst.n 0xb098
.align 2
ldr.w pc,[pc,#0]
.word 0xb799e9
original art_queue,0xe92d0700,0xb79abd
original publish,0xf84d8d04,0x35c555
