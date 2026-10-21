#ifndef PHOTO_LUT_LIFETIME_H
#define PHOTO_LUT_LIFETIME_H
/* Caller owns one aligned cell per independently reusable photo context.
 * Initialize once to PLL_FREE before publishing; never reset a live cell.
 * This tracks photo readers only. It is not permission to release a shared
 * resource while an untracked native reader or loader still owns it.
 */
typedef unsigned int pll_u32;
struct pll_cell { pll_u32 word; };
enum { PLL_SUBMIT = 0x10, PLL_LOAD = 0x20, PLL_FAULT = 0x40,
       PLL_FREE = 0x80, PLL_RELEASING = 0xc0 };
/* Begin increments a 24-bit nonwrapping epoch. Zero means busy/exhausted/bad
 * mask. Returned tag has the native type byte 2 and the epoch in bits 8..31. */
pll_u32 pll_begin(struct pll_cell *, pll_u32 enabled_channels);
/* Events are idempotent, reject stale epochs, and cannot clear a fault.
 * Completion failure quarantines the cell, including ambiguous submission.
 * A VFX channel number follows the original callback ABI: 3..6.
 */
pll_u32 pll_load_complete(struct pll_cell *, pll_u32 tag, pll_u32 success);
pll_u32 pll_submit_complete(struct pll_cell *, pll_u32 tag, pll_u32 success);
pll_u32 pll_vfx_complete(struct pll_cell *, pll_u32 tag, pll_u32 channel, pll_u32 error);
pll_u32 pll_fault(struct pll_cell *, pll_u32 tag);
/* One caller may claim a fully completed photo. It must still satisfy shared
 * native ownership and buffer rules before invoking any real release API. */
pll_u32 pll_take_release(struct pll_cell *, pll_u32 tag);
pll_u32 pll_release_complete(struct pll_cell *, pll_u32 tag, pll_u32 success);
#endif
