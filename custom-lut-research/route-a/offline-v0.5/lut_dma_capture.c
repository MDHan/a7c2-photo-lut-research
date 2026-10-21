/* Deferred completion capture. No application callback runs in this hook. */
typedef unsigned int u32;
#define STATE ((u32 *)0x1b85ff8U)
void lut_dma_capture(int status) {
    u32 expected=1;
    u32 result=status==0?2U:(status<0?(u32)status:(u32)-6);
    __atomic_compare_exchange_n(STATE,&expected,result,0,__ATOMIC_RELEASE,__ATOMIC_RELAXED);
}
