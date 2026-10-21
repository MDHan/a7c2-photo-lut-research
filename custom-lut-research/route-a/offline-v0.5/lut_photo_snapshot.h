/* Exact-build photo guard: take a parent read lease before the reusable
 * entry can read G's shared LUT descriptor. Accepted queue messages hold
 * separate leases, so a photo timeout cannot release their source bytes.
 */
#include <stdarg.h>
INLINE void photo_snapshot(u32 *result,u32 module,u32 parameter,u32 stage,u32 **raw) {
    typedef void (*photo)(u32 *,u32,u32,u32,u32 *,u32 *,u32 *,u32 *);
    u32 mask=0;
    for(u32 i=0;i<4;i++) if(raw[i] && raw[i][0x1c8/4]) mask|=1U<<i;
    volatile u32 *g=(volatile u32 *)0x165a720U;
    /* Match the entry's original bypass exactly. Call the native bypass
     * directly, rather than reevaluating eligibility without a lease. */
    if(!mask || g[0xaf8/4]!=10 || g[0xafc/4]!=0) {
        ((photo)0x480f29U)(result,module,parameter,stage,raw[0],raw[1],raw[2],raw[3]);
        return;
    }
    u32 token=((u32 (*)(struct lh_cp *))CP_READER_BEGIN)(CP);
    if(!token) {
        ((unsigned char *)result)[0]=0;
        result[1]=0xc17e000bU;
        return;
    }
    ((photo)LUT_REUSABLE_PHOTO_ENTRY)(result,module,parameter,stage,raw[0],raw[1],raw[2],raw[3]);
    if(!reader_end(token,0)) quarantine();
}
