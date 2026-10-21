#ifndef LUT_DMA_CAPTURE
#include "lifecycle-dev/reader-placement-build/layout.h"
#endif
#include "lut_handoff_cp.h"
#define LUT_DMA_CUSTOM_DISPATCH
#include "lut_dma_worker.c"

#define CP ((struct lh_cp *)0x1b85f64U)
INLINE u32 reader_end(u32 token,int failed) {
    return ((u32 (*)(struct lh_cp *,u32))(failed?CP_READER_FAULT:CP_READER_END))(CP,token);
}
INLINE int reader_active(u32 token) {
    u32 slot=token&31U,epoch=token>>5;
    return slot<LH_CP_READERS && epoch &&
        __atomic_load_n(&CP->readers[slot],__ATOMIC_ACQUIRE)==(0x80000000U|epoch) &&
        (__atomic_load_n(CP_GATE,__ATOMIC_ACQUIRE)&(1U<<slot));
}
INLINE void quarantine(void) {
    __atomic_store_n(STATE,FAULT,__ATOMIC_RELEASE);
    __atomic_fetch_or(CP_GATE,0x20000000U,__ATOMIC_ACQ_REL);
}
INLINE int enqueue_reader(const u32 *message) {
    if((message[0]!=1 && message[0]!=3) || message[1]) return -20;
    u32 token=((u32 (*)(struct lh_cp *))CP_READER_BEGIN)(CP);
    if(!token) return -20;
    u32 copy[14];
    for(u32 i=0;i<14;i++) copy[i]=message[i];
    copy[1]=token;
    int result=((int (*)(const u32 *))0xb83283U)(copy);
    if(result && !reader_end(token,0)) quarantine();
    return result;
}

#ifdef LUT_PHOTO_SNAPSHOT_GUARD
#include "lut_photo_snapshot.h"
#endif
#ifdef LUT_NATIVE_SNAPSHOT_GUARD
#include "lut_native_snapshot.h"
#endif

/* Both native type-1/type-3 constructors use this shared veneer before their
 * native queue call; the worker uses it for dispatch. LR distinguishes the
 * two exact-build enqueue sites, without adding a global producer token.
 */
int lut_dma_dispatch(const u32 *message
#if defined(LUT_PHOTO_SNAPSHOT_GUARD) || defined(LUT_NATIVE_SNAPSHOT_GUARD)
    , ...
#endif
) {
    u32 caller=(u32)__builtin_return_address(0)&~1U;
#ifdef LUT_NATIVE_IPC_INGRESS
    if(caller==0x4b3b30U) {
        va_list args;
        va_start(args,message);
        u32 port=va_arg(args,u32);
        va_end(args);
        return ((int (*)(const void *,u32))CP_INGRESS_ENTRY)(message,port);
    }
#endif
#ifdef LUT_NATIVE_SNAPSHOT_GUARD
    if(caller==0x4c2eb2U || caller==0xb2b4d8U || caller==0xb2b59aU || caller==0xb2ba12U) {
        va_list args;
        va_start(args,message);
        const u32 *context=va_arg(args,const u32 *);
        va_end(args);
        native_snapshot((u32)message,context);
        return 0;
    }
#endif
#ifdef LUT_PHOTO_SNAPSHOT_GUARD
    if(caller==0x48c744U) {
        va_list args;
        va_start(args,message);
        u32 module=va_arg(args,u32),parameter=va_arg(args,u32),stage=va_arg(args,u32);
        u32 *raw[4];
        for(u32 i=0;i<4;i++) raw[i]=va_arg(args,u32 *);
        va_end(args);
        photo_snapshot((u32 *)message,module,parameter,stage,raw);
        return 0; /* The native photo ABI returns its result through memory. */
    }
#endif
    if(caller==0xb79a6eU || caller==0xb79b3eU) return enqueue_reader(message);
    int data=message[0]==1 || message[0]==3;
    u32 token=data?message[1]:0;
    if(data && !reader_active(token)) {quarantine();return reject((callback)message[3]);}
    if(__atomic_load_n(STATE,__ATOMIC_ACQUIRE) ||
       (__atomic_load_n(CP_GATE,__ATOMIC_ACQUIRE)&0x20000000U)) {
        /* This message has not entered its native data handler or DMA. */
        if(data && !reader_end(token,0)) quarantine();
        return reject((callback)message[3]);
    }
    int result=((int (*)(const u32 *))0x53533dU)(message);
    if(data && !reader_end(token,result!=0)) quarantine();
    return result;
}
