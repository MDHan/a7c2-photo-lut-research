/* Exact-build ILCE-7CM2 2.01 offline candidate. No runtime allocation.
 * Enter only from the native photo VFX call at 0x48c740.
 * Hardware output and concurrent native ownership still require device tests.
 */
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
enum { BAD_INPUT=1, LOAD_FAILED=2, LUT_CHANGED=3, LOAD_TIMEOUT=6, DELAY_FAILED=7 };
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
    for (u32 i=0;i<4;i++) if (mask&(1U<<i)) raw[i][0x234/4]=1;
    ((submit)0x480f29U)(result,module,parameter_context,stage,raw0,raw1,raw2,raw3);
    if (!(((u8 *)result)[0]&1U) || result[1])
        for (u32 i=0;i<4;i++) if (mask&(1U<<i)) raw[i][0x234/4]=old[i];
    return;
original:
    ((submit)0x480f29U)(result,module,parameter_context,stage,raw0,raw1,raw2,raw3);
    return;
reject:
    /* Do not clear native pending/state or fake cancellation. The driver's
     * queued request uses copied data and its own static completion callback.
     * A callsite guard routes these errors to native capture failure once. */
    ((u8 *)result)[0]=0; result[1]=0xc17e0000U|error;
}
