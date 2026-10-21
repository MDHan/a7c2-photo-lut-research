#include "photo_lut_completion.h"
#define INLINE static __attribute__((always_inline)) inline
#define EPOCH 0xfffff000U
_Static_assert(sizeof(struct pll_cell)==4, "existing BSS cell ABI");
INLINE pll_u32 read_word(struct pll_cell *c) {
    return __atomic_load_n(&c->word, __ATOMIC_ACQUIRE);
}
INLINE pll_u32 exchange(struct pll_cell *c, pll_u32 *old, pll_u32 next) {
    return __atomic_compare_exchange_n(&c->word,old,next,0,
                                       __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
}
INLINE pll_u32 valid(pll_u32 tag) { return (tag&~EPOCH)==2 && (tag&EPOCH)!=0; }
pll_u32 pll_begin(struct pll_cell *c, pll_u32 mask) {
    if (!mask || (mask&~15U)) return 0;
    pll_u32 old=read_word(c);
    for (;;) {
        pll_u32 state=old&~EPOCH;
        if ((state!=PLL_FREE && (state!=0 || !(old&EPOCH))) ||
            (old&EPOCH)==EPOCH) return 0;
        pll_u32 epoch=(old&EPOCH)+0x1000U;
        if (exchange(c,&old,epoch|PLL_SUBMIT|PLL_LOAD|mask)) return epoch|2U;
    }
}
INLINE pll_u32 event(struct pll_cell *c, pll_u32 tag, pll_u32 clear, pll_u32 error) {
    if (!valid(tag)) return 0;
    pll_u32 old=read_word(c), epoch=tag&EPOCH;
    for (;;) {
        if ((old&EPOCH)!=epoch || (old&(PLL_FREE|PLL_FAULT))) return 0;
        if (exchange(c,&old,error ? old|PLL_FAULT : old&~clear)) return 1;
    }
}
pll_u32 pll_load_complete(struct pll_cell *c, pll_u32 tag, pll_u32 ok) {
    return event(c,tag,PLL_LOAD,!ok);
}
pll_u32 pll_submit_complete(struct pll_cell *c, pll_u32 tag, pll_u32 ok) {
    return event(c,tag,PLL_SUBMIT,!ok);
}
pll_u32 pll_fault(struct pll_cell *c, pll_u32 tag) { return event(c,tag,0,1); }
pll_u32 pll_callback_claim(struct pll_cell *c, pll_u32 tag, pll_u32 channel) {
    if (!valid(tag) || channel<3 || channel>6) return 0;
    pll_u32 pending=1U<<(channel-3), in_flight=pending<<8;
    pll_u32 old=read_word(c), epoch=tag&EPOCH;
    for (;;) {
        if ((old&EPOCH)!=epoch || (old&(PLL_FREE|PLL_FAULT|in_flight)) ||
            !(old&pending)) return 0;
        if (exchange(c,&old,old|in_flight)) return 1;
    }
}
pll_u32 pll_callback_finish(struct pll_cell *c, pll_u32 tag, pll_u32 channel, pll_u32 error) {
    if (!valid(tag) || channel<3 || channel>6) return 0;
    pll_u32 pending=1U<<(channel-3), in_flight=pending<<8;
    pll_u32 old=read_word(c), epoch=tag&EPOCH;
    for (;;) {
        if ((old&EPOCH)!=epoch || !(old&in_flight) || (old&PLL_FREE)) return 0;
        pll_u32 next=old&~in_flight;
        next=error ? next|PLL_FAULT : next&~pending;
        /* A simultaneous submit/load fault remains sticky even after a
         * previously claimed notification returns successfully. */
        if (exchange(c,&old,next)) return 1;
    }
}
