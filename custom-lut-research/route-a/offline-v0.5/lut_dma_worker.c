/* Prototype: actual native wait and dispatch, deferred completion, cold-only
 * fault isolation. Final code placement and cold initialization are pending.
 */
#ifndef LUT_DMA_CAPTURE
#include "lifecycle-dev/dma-worker-build/layout.h"
#endif
typedef unsigned int u32;
typedef void (*callback)(int);
#define STATE ((u32 *)0x1b85ff8U)
#define CP_GATE ((u32 *)0x1b85f68U)
#define FAULT 3U
#define INLINE static __attribute__((always_inline)) inline
INLINE void notify(callback done,int result) { if(done) done(result); }
INLINE int reject(callback done) { notify(done,-20);return -20; }

int lut_dma_run(void *descriptor,callback done) {
    u32 expected=0;
    if(!__atomic_compare_exchange_n(STATE,&expected,1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return reject(done);
    int result=((int (*)(void *,callback))0xb83063U)(descriptor,(callback)LUT_DMA_CAPTURE);
    u32 captured=__atomic_load_n(STATE,__ATOMIC_ACQUIRE);
    if(!result) result=captured==2?0:((int)captured<0?(int)captured:-20);
    if(result) {
        __atomic_store_n(STATE,FAULT,__ATOMIC_RELEASE);
        __atomic_fetch_or(CP_GATE,0x20000000U,__ATOMIC_ACQ_REL);
    }
    /* Keep SUCCESS or FAULT published while the application callback runs.
     * Reentrant dispatch cannot replace the native global completion pointer. */
    notify(done,result);
    if(!result) __atomic_store_n(STATE,0,__ATOMIC_RELEASE);
    return result;
}

#ifndef LUT_DMA_CUSTOM_DISPATCH
int lut_dma_dispatch(const u32 *message) {
    if(__atomic_load_n(STATE,__ATOMIC_ACQUIRE))
        return reject((callback)message[3]);
    return ((int (*)(const u32 *))0x53533dU)(message);
}
#endif
