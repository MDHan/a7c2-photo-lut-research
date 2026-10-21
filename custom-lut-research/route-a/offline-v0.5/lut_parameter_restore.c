#include "lifecycle-dev/cp-ingress-placement/layout.h"
typedef unsigned int u32;
typedef unsigned short u16;
_Static_assert(sizeof(u32)==4 && sizeof(u16)==2,"codec word sizes");

/* Exact-build boot stream, checked by the builder and image hash. Decode to
 * reserved scratch first so restoring native parameter addresses cannot
 * overwrite unread source or code. No allocator, OS or external helper call. */
void lut_restore_parameters(void) {
    const volatile u16 *source=(const volatile u16 *)LUT_PACKED_PARAMETERS;
    volatile u32 *scratch=(volatile u32 *)LUT_PARAMETER_SCRATCH;
    for(u32 i=0;i<LUT_PARAMETER_WORDS;i++) {
        u32 value=*source++;
        if(value==65535) {
            value=*source++;
            value|=(u32)*source++<<16;
        }
        scratch[i]=value;
    }
    volatile u32 *destination=(volatile u32 *)LUT_NATIVE_PARAMETERS;
    for(u32 i=0;i<LUT_PARAMETER_WORDS;i++) {
        destination[i]=scratch[i];
        u32 line=(u32)(destination+i)&~31U;
        __asm__ volatile("mcr p15,0,%0,c7,c10,1" :: "r"(line) : "memory");
    }
    __asm__ volatile("dsb sy" ::: "memory");
    ((void (*)(u32))0x60d35cU)(0xa000U);
}
