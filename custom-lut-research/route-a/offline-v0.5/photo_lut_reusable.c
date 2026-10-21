/* Experimental exact-build photo entry with reusable completion tracking.
 * Derived from frozen photo_lut.c; not installed or flash-ready.
 */
#include "photo_lut_completion.h"
#include "lifecycle-dev/reuse-build/layout.h"
typedef unsigned int u32;
typedef unsigned char u8;
typedef int s32;
#define W(a) (*(volatile u32 *)(a))
#define B(a) (*(volatile u8 *)(a))
#define INLINE static __attribute__((always_inline)) inline
#define G 0x165a720U
#define STATE 0x1a6aefcU
#define PENDING 0x1b1e235U
#define RESERVATION 0x1a7e608U
enum { BAD_INPUT=1, LOAD_FAILED=2, LUT_CHANGED=3, LOAD_TIMEOUT=6, DELAY_FAILED=7, CONTEXT_BUSY=8, BAD_CONTEXT=9, SUBMIT_FAILED=10 };
struct snapshot { u32 ctx[30], input, target, generation; };
_Static_assert(sizeof(u32)==4, "CP ABI");

INLINE u32 same(const struct snapshot *s) {
    if (W(G+0x684)!=s->generation || W(G+0xaf8)!=10 || W(G+0xafc)!=0 ||
        W(G+0xb00)!=s->input || W(G+0xb04)!=s->ctx[3] || W(G+0xb08)!=s->target)
        return 0;
    for (u32 i=0;i<24;i++) if (W(G+0x68+4*i)!=s->ctx[6+i]) return 0;
    /* Detect a receiver update that occurred during the comparison. This is
     * change detection, not a lock or a backing-buffer lifetime guarantee. */
    return W(G+0x684)==s->generation;
}
INLINE u32 snapshot(struct snapshot *s) {
    typedef u32 (*selector)(u32,u32,u32,u32,u32,u32);
    s->generation=W(G+0x684); s->input=W(G+0xb00); s->target=W(G+0xb08);
    s->ctx[1]=0; s->ctx[2]=10; s->ctx[3]=W(G+0xb04);
    s->ctx[4]=0; s->ctx[5]=0;
    for (u32 i=0;i<24;i++) s->ctx[6+i]=W(G+0x68+4*i);
    if (!same(s)) return LUT_CHANGED;
    /* Native b799de requires 0xbb80 bytes for the registered hardware LUT;
     * optional ArtGen b79ab4 requires 0x7c. Reject invalid descriptors before
     * taking a driver reservation, not after a native upload rejects them. */
    if ((!s->ctx[6] && !s->ctx[7]) || s->ctx[10]!=0xbb80U) return BAD_INPUT;
    if (s->ctx[11] && (s->ctx[11]!=0x7cU || (!s->ctx[8] && !s->ctx[9])))
        return BAD_INPUT;
    s->ctx[0]=((selector)0x4e8a5dU)(0,10,s->ctx[3],s->input,s->target,s->ctx[11]);
    if (!s->ctx[0] || s->ctx[0]>=30) return BAD_INPUT;
    return same(s) ? 0 : LUT_CHANGED;
}
INLINE u32 ready(const struct snapshot *s) {
    typedef u32 (*predicate)(u32,u32,const u32 *);
    if (W(STATE)!=2 || B(PENDING)!=0) return 0;
    return ((predicate)0xb31a55U)(s->ctx[0],10,s->ctx+6);
}

void photo_vfx_once(u32 *result,u32 module,u32 parameter_context,u32 stage,
                    u32 *raw0,u32 *raw1,u32 *raw2,u32 *raw3) {
    typedef void (*submit)(u32 *,u32,u32,u32,u32 *,u32 *,u32 *,u32 *);
    typedef void (*apply)(u32,const u32 *);
    typedef s32 (*delay)(u32);
    struct snapshot s;
    struct pll_cell *cell=0;
    u32 tag=0, callback=0, saved_word[4], saved_callback[4];
    u32 *raw[4]={raw0,raw1,raw2,raw3};
    u32 mask=0, old[4]={0,0,0,0}, error=0, calls=0, issued=0;
    for (u32 i=0;i<4;i++) if (raw[i] && raw[i][0x1c8/4]) mask|=1U<<i;
    if (!mask || W(G+0xaf8)!=10 || W(G+0xafc)!=0) goto original;
    error=snapshot(&s); if (error) goto reject;
    for (u32 i=0;i<4;i++) if (mask&(1U<<i)) {
        if (raw[i][0x1c8/4]!=0x10000U || raw[i][0x234/4]>1) {
            error=BAD_INPUT; goto reject;
        }
        old[i]=raw[i][0x234/4];
    }
    if (!module || !W(module+0x24)) { error=BAD_INPUT; goto reject; }
    /* Native module kinds map positional RAW arguments to hardware channels.
     * 3..6: raw0 -> channel 0..3; 7/8: raw0..1 -> 0..1/2..3;
     * 9: raw0..3 -> all four. Track only the arguments actually submitted. */
    u32 kind=W(module+0x12c), count, shift;
    if (kind>=3 && kind<=6) { count=1; shift=kind-3; }
    else if (kind==7 || kind==8) { count=2; shift=kind==7 ? 0 : 2; }
    else if (kind==9) { count=4; shift=0; }
    else { error=BAD_INPUT; goto reject; }
    mask&=(1U<<count)-1U;
    if (!mask) { error=BAD_INPUT; goto reject; }
    if (stage==0x17233f0U) {
        cell=(struct pll_cell *)0x1b85f5cU;
        callback=PHOTO_CALLBACK0;
    } else if (stage==0x1724080U) {
        cell=(struct pll_cell *)0x1b85f60U;
        callback=PHOTO_CALLBACK1;
    } else { error=BAD_CONTEXT; goto reject; }
    for (u32 i=0;i<count;i++) if (mask&(1U<<i)) {
        saved_word[i]=raw[i][0x318/4];
        saved_callback[i]=raw[i][0x31c/4];
        if ((saved_word[i]&255U)!=2 ||
            saved_callback[i]!=(stage==0x17233f0U ? 0xb1920bU : 0xb19217U)) {
            error=BAD_CONTEXT; goto reject;
        }
    }
    tag=((u32 (*)(struct pll_cell *,u32))PLL_BEGIN)(cell,mask<<shift);
    if (!tag) { error=CONTEXT_BUSY; goto reject; }
    for (u32 waits=0;;) {
        if (!same(&s)) { error=LUT_CHANGED; goto reject; }
        if (ready(&s)) break;
        if (!B(PENDING)) {
            if (issued) { error=LOAD_FAILED; goto reject; }
            /* Do not consume another owner's outstanding acquisition. */
            if (W(STATE)!=1 || W(RESERVATION)==W(module+0x24)) {
                if (calls==2) { error=LOAD_FAILED; goto reject; }
                calls++;
                ((apply)0x4e876dU)(W(module+0x24),s.ctx);
                if (!W(STATE)) { error=LOAD_FAILED; goto reject; }
                /* Acquisition and load are separate native calls. Continue
                 * immediately while holding our reservation, without sleep
                 * or a new rejection point between acquisition and load. */
                if (W(STATE)==1 && W(RESERVATION)==W(module+0x24) && calls<2) {
                    calls++;
                    ((apply)0x4e876dU)(W(module+0x24),s.ctx);
                    if (!W(STATE)) { error=LOAD_FAILED; goto reject; }
                }
                if (W(STATE)==2) issued=1;
                if (ready(&s)) break;
            }
        }
        if (waits++==150) { error=LOAD_TIMEOUT; goto reject; }
        if (((delay)0x5f4144U)(20)!=0) { error=DELAY_FAILED; goto reject; }
    }
    if (!same(&s) || !ready(&s)) { error=LUT_CHANGED; goto reject; }
    ((u32 (*)(struct pll_cell *,u32,u32))PLL_LOAD_COMPLETE)(cell,tag,1);
    for (u32 i=0;i<4;i++) if (mask&(1U<<i)) {
        raw[i][0x234/4]=1;
        raw[i][0x318/4]=tag;
        raw[i][0x31c/4]=callback;
    }
    ((submit)0x480f29U)(result,module,parameter_context,stage,raw0,raw1,raw2,raw3);
    if (!(((u8 *)result)[0]&1U) || result[1]) {
        ((u32 (*)(struct pll_cell *,u32,u32))PLL_SUBMIT_COMPLETE)(cell,tag,0);
        for (u32 i=0;i<4;i++) if (mask&(1U<<i)) {
            raw[i][0x234/4]=old[i];
            raw[i][0x318/4]=saved_word[i];
            raw[i][0x31c/4]=saved_callback[i];
        }
        error=SUBMIT_FAILED; goto reject;
    }
    ((u32 (*)(struct pll_cell *,u32,u32))PLL_SUBMIT_COMPLETE)(cell,tag,1);
    return;
original:
    ((submit)0x480f29U)(result,module,parameter_context,stage,raw0,raw1,raw2,raw3);
    return;
reject:
    /* A queued descriptor does not pin the backing LUT bytes. Keep failures
     * quarantined; the verified native drain/release path is still pending.
     * A BUSY rejection has no new tag and cannot fault the existing request. */
    if (tag) ((u32 (*)(struct pll_cell *,u32))PLL_FAULT)(cell,tag);
    ((u8 *)result)[0]=0; result[1]=0xc17e0000U|error;
}
