/* Experimental freestanding lifecycle core, not yet deployed in firmware. */
#include "photo_lut_lifetime.h"
#define INLINE static __attribute__((always_inline)) inline
_Static_assert(sizeof(pll_u32) == 4, "CP word ABI");
_Static_assert(sizeof(struct pll_cell) == 4, "one atomic word");
INLINE pll_u32 read_word(struct pll_cell *c) {
    return __atomic_load_n(&c->word, __ATOMIC_ACQUIRE);
}
INLINE pll_u32 exchange(struct pll_cell *c, pll_u32 *old, pll_u32 next) {
    return __atomic_compare_exchange_n(&c->word, old, next, 0,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}
INLINE pll_u32 tag_valid(pll_u32 tag) {
    return (tag & 255U) == 2 && (tag >> 8) != 0;
}
pll_u32 pll_begin(struct pll_cell *c, pll_u32 mask) {
    if (!mask || (mask & ~15U)) return 0;
    pll_u32 old = read_word(c);
    for (;;) {
        if ((old & 255U) != PLL_FREE || (old >> 8) == 0xffffffU) return 0;
        pll_u32 epoch = (old & ~255U) + 256U;
        if (exchange(c, &old, epoch | PLL_SUBMIT | PLL_LOAD | mask))
            return epoch | 2U;
    }
}
INLINE pll_u32 event(struct pll_cell *c, pll_u32 tag, pll_u32 clear, pll_u32 error) {
    if (!tag_valid(tag)) return 0;
    pll_u32 epoch = tag & ~255U, old = read_word(c);
    for (;;) {
        if ((old & ~255U) != epoch || (old & (PLL_FREE | PLL_FAULT))) return 0;
        pll_u32 next = error ? old | PLL_FAULT : old & ~clear;
        if (exchange(c, &old, next)) return 1;
    }
}
pll_u32 pll_load_complete(struct pll_cell *c, pll_u32 tag, pll_u32 success) {
    return event(c, tag, PLL_LOAD, !success);
}
pll_u32 pll_submit_complete(struct pll_cell *c, pll_u32 tag, pll_u32 success) {
    return event(c, tag, PLL_SUBMIT, !success);
}
pll_u32 pll_vfx_complete(struct pll_cell *c, pll_u32 tag, pll_u32 channel, pll_u32 error) {
    if (channel < 3 || channel > 6) return 0;
    return event(c, tag, 1U << (channel - 3), error);
}
pll_u32 pll_fault(struct pll_cell *c, pll_u32 tag) {
    return event(c, tag, 0, 1);
}
pll_u32 pll_take_release(struct pll_cell *c, pll_u32 tag) {
    if (!tag_valid(tag)) return 0;
    pll_u32 epoch = tag & ~255U, old = epoch;
    return exchange(c, &old, epoch | PLL_RELEASING);
}
pll_u32 pll_release_complete(struct pll_cell *c, pll_u32 tag, pll_u32 success) {
    if (!tag_valid(tag)) return 0;
    pll_u32 epoch = tag & ~255U, old = epoch | PLL_RELEASING;
    return exchange(c, &old, epoch | (success ? PLL_FREE : PLL_FAULT));
}
