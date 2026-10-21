/* Tagged callbacks with the native event IDs, masks, diagnostics and OS ABI.
 * Capture notification status directly: the original callback's logging tail
 * can overwrite a failed set-event return value.
 */
#include "photo_lut_completion.h"
#include "lifecycle-dev/reuse-build/layout.h"
typedef unsigned int u32;
#define INLINE static __attribute__((always_inline)) inline
INLINE void notify(u32 address,u32 event,u32 error,u32 owner,u32 channel,u32 tag) {
    typedef u32 (*claim_fn)(struct pll_cell *,u32,u32);
    typedef u32 (*finish_fn)(struct pll_cell *,u32,u32,u32);
    typedef void (*log_fn)(u32,u32,u32,u32);
    typedef int (*signal_fn)(u32,u32);
    struct pll_cell *cell=(struct pll_cell *)address;
    if (!((claim_fn)PLL_CALLBACK_CLAIM)(cell,tag,channel)) return;
    u32 mask=1U<<(channel+9);
    ((log_fn)0xb4361dU)(4,0x402a,mask,owner);
    if (error) {
        ((log_fn)0xb4457bU)(0xfc2629,0x49f1e4,0x430,error);
    } else {
        error=(u32)((signal_fn)0x5e9a7cU)(event,mask);
        if (error) ((log_fn)0xb4457bU)(0xfc2543,0x49f1e4,0x437,error);
    }
    ((finish_fn)PLL_CALLBACK_FINISH)(cell,tag,channel,error);
}
void photo_context0(u32 error,u32 owner,u32 channel,u32 tag) {
    notify(0x1b85f5c,0x32,error,owner,channel,tag);
}
void photo_context1(u32 error,u32 owner,u32 channel,u32 tag) {
    notify(0x1b85f60,0x33,error,owner,channel,tag);
}
