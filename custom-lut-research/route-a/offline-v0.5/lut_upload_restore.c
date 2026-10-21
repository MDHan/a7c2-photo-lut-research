#include "lifecycle-dev/upload-cp-build/layout.h"
typedef unsigned int u32;
void lut_restore_parameters(void) {
    const volatile unsigned char *p=(const volatile unsigned char *)LUT_PACKED_PARAMETERS;
    volatile unsigned char *scratch=(volatile unsigned char *)LUT_PARAMETER_SCRATCH;
    u32 written=0;
    while(written<LUT_PARAMETER_WORDS*4) {
        u32 command=*p++,n;
        if(command<128) {
            n=command+1;
            while(n--) scratch[written++]=*p++;
        } else {
            n=(command&127)+3;
            u32 distance=*p++;distance|=(u32)*p++<<8;
            while(n--) {scratch[written]=scratch[written-distance];written++;}
        }
    }
    volatile u32 *destination=(volatile u32 *)LUT_NATIVE_PARAMETERS;
    volatile u32 *words=(volatile u32 *)LUT_PARAMETER_SCRATCH;
    for(u32 i=0;i<LUT_PARAMETER_WORDS;i++) {
        destination[i]=words[i];
        u32 line=(u32)(destination+i)&~31U;
        __asm__ volatile("mcr p15,0,%0,c7,c10,1" :: "r"(line):"memory");
    }
    __asm__ volatile("dsb sy" ::: "memory");
    ((void (*)(u32))0x60d35cU)(0xa000U);
}
