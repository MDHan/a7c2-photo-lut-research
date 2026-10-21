#ifndef PHOTO_LUT_COMPLETION_H
#define PHOTO_LUT_COMPLETION_H
/* Photo tracking only: this cell does not own a shared native LUT allocation.
 * Each pending channel remains set until its event notification returns.
 * Bits 8..11 claim notifications independently; epoch is nonwrapping 20 bits.
 */
typedef unsigned int pll_u32;
struct pll_cell { pll_u32 word; };
enum { PLL_SUBMIT=0x10, PLL_LOAD=0x20, PLL_FAULT=0x40, PLL_FREE=0x80 };
pll_u32 pll_begin(struct pll_cell *, pll_u32);
pll_u32 pll_load_complete(struct pll_cell *, pll_u32, pll_u32);
pll_u32 pll_submit_complete(struct pll_cell *, pll_u32, pll_u32);
pll_u32 pll_fault(struct pll_cell *, pll_u32);
pll_u32 pll_callback_claim(struct pll_cell *, pll_u32, pll_u32);
pll_u32 pll_callback_finish(struct pll_cell *, pll_u32, pll_u32, pll_u32);
#endif
