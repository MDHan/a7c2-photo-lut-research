#include "lut_handoff_cp.h"
#define INLINE static __attribute__((always_inline)) inline
#define CLOSED 0x80000000U
#define INVALID 0x40000000U
#define FAULT 0x20000000U
#define READERS 0x1fffffffU
#define EPOCH 0x07ffffffU
#define ACTIVE 0x80000000U
#define FAILED 0x40000000U
_Static_assert(sizeof(struct lh_cp)==148,"CP state ABI");
INLINE lh_u32 load(lh_u32 *p) { return __atomic_load_n(p,__ATOMIC_ACQUIRE); }
INLINE lh_u32 cas(lh_u32 *p,lh_u32 *old,lh_u32 next) {
    return __atomic_compare_exchange_n(p,old,next,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
}
INLINE lh_u32 take(struct lh_cp *c) { lh_u32 zero=0; return cas(&c->lock,&zero,1); }
INLINE void give(struct lh_cp *c) { __atomic_store_n(&c->lock,0,__ATOMIC_RELEASE); }
INLINE lh_u32 get32(const unsigned char *p) {
    return (lh_u32)p[0]|((lh_u32)p[1]<<8)|((lh_u32)p[2]<<16)|((lh_u32)p[3]<<24);
}
INLINE void put32(unsigned char *p,lh_u32 x) {
    p[0]=x;p[1]=x>>8;p[2]=x>>16;p[3]=x>>24;
}
INLINE void response(unsigned char *p,lh_u32 id,lh_u32 op,lh_u32 status,
                     lh_u32 lo,lh_u32 hi,lh_u32 generation) {
    put32(p,((lh_u32)LH_COMMAND<<16)|1U);put32(p+4,id);put32(p+8,LH_MAGIC);
    put32(p+12,1U|(op<<16)|(status<<24));put32(p+16,lo);put32(p+20,hi);
    put32(p+24,generation);put32(p+28,0);
}
lh_u32 lh_cp_open(struct lh_cp *c,lh_u32 lo,lh_u32 hi,lh_u32 generation) {
    if (!(lo|hi) || !take(c)) return 0;
    lh_u32 result=0;
    if (!c->initialized) {
        c->session_lo=lo;c->session_hi=hi;c->generation=generation;
        c->initialized=1;result=1;
    }
    give(c);return result;
}
lh_u32 lh_cp_reader_begin(struct lh_cp *c) {
    /* Bounded CAS attempts: a preempted reader/IRQ never spins on a mutex.
     * Reserve its bit before publishing the token, so a writer observes it. */
    for (lh_u32 i=0;i<LH_CP_READERS;i++) {
        if ((load(&c->readers[i])&EPOCH)==EPOCH) continue;
        lh_u32 bit=1U<<i;
        for (lh_u32 tries=0;tries<4;tries++) {
            lh_u32 old=load(&c->gate);
            if (old&(CLOSED|INVALID|FAULT)) return 0;
            if (old&bit) break;
            if (!cas(&c->gate,&old,old|bit)) continue;
            lh_u32 epoch=load(&c->readers[i])&EPOCH;
            if (epoch==EPOCH) {
                __atomic_fetch_and(&c->gate,~bit,__ATOMIC_ACQ_REL);break;
            }
            ++epoch;
            __atomic_store_n(&c->readers[i],ACTIVE|epoch,__ATOMIC_RELEASE);
            return (epoch<<5)|i;
        }
    }
    return 0;
}
lh_u32 lh_cp_reader_end(struct lh_cp *c,lh_u32 token) {
    lh_u32 i=token&31,epoch=token>>5;
    if (i>=LH_CP_READERS || !epoch) return 0;
    lh_u32 old=ACTIVE|epoch;
    if (!cas(&c->readers[i],&old,epoch)) return 0;
    __atomic_fetch_and(&c->gate,~(1U<<i),__ATOMIC_ACQ_REL);
    return 1;
}
lh_u32 lh_cp_reader_fault(struct lh_cp *c,lh_u32 token) {
    lh_u32 i=token&31,epoch=token>>5;
    if (i>=LH_CP_READERS || !epoch) return 0;
    lh_u32 old=ACTIVE|epoch;
    if (!cas(&c->readers[i],&old,FAILED|epoch)) return old==(FAILED|epoch);
    /* Retain the reader bit. Unknown DMA completion is not a normal release. */
    __atomic_fetch_or(&c->gate,FAULT,__ATOMIC_ACQ_REL);
    return 1;
}
lh_u32 lh_cp_request(struct lh_cp *c,const unsigned char *p,lh_u32 n,unsigned char *out) {
    if (n<12 || p[0]!=5 || p[2]!=0x55 || p[3]!=0x41 || get32(p+8)!=LH_MAGIC)
        return LH_CP_NOT_OURS;
    if (n!=32 || p[1] || p[12]!=1 || p[13] || p[15] || get32(p+28) ||
        p[14]<LH_ACQUIRE || p[14]>LH_CANCEL) return LH_CP_DROP;
    lh_u32 id=get32(p+4),op=p[14],lo=get32(p+16),hi=get32(p+20);
    if (!id || id>0x0fffffffU || !take(c)) return LH_CP_DROP;
    lh_u32 status=2,result=LH_CP_REPLY;
    if (!c->initialized || lo!=c->session_lo || hi!=c->session_hi || id<c->last_id)
        goto reply;
    if (id>c->last_id) {
        if (c->phase==LH_CP_WAIT || c->phase==LH_CP_HELD || c->phase==LH_CP_PUBLISHING) {
            status=1;goto reply;
        }
        if (op==LH_CANCEL) {
            /* Tombstone first: a delayed ACQUIRE with this ID cannot reopen. */
            c->last_id=id;c->phase=LH_CP_CANCELLED;status=0;goto reply;
        }
        if (op!=LH_ACQUIRE) goto reply;
        c->last_id=id;c->phase=LH_CP_WAIT;
        __atomic_fetch_or(&c->gate,CLOSED,__ATOMIC_ACQ_REL);
    }
    if (op==LH_ACQUIRE) {
        if (c->phase==LH_CP_HELD) {status=0;goto reply;}
        if (c->phase!=LH_CP_WAIT) goto reply;
        lh_u32 gate=load(&c->gate);
        if (gate&FAULT) goto reply;
        if (gate&READERS) {status=1;goto reply;}
        /* Permission may allow an in-place partial write. Treat the buffer as
         * invalid until descriptor publication succeeds, even if AP cancels. */
        __atomic_fetch_or(&c->gate,INVALID,__ATOMIC_ACQ_REL);
        c->phase=LH_CP_HELD;status=0;
    } else if (op==LH_CANCEL) {
        if (c->phase==LH_CP_PUBLISHING) {status=1;goto reply;}
        if (c->phase!=LH_CP_COMMITTED) c->phase=LH_CP_CANCELLED;
        __atomic_fetch_and(&c->gate,~CLOSED,__ATOMIC_ACQ_REL);
        status=0;
    } else {
        if (c->phase==LH_CP_COMMITTED) {status=0;goto reply;}
        if (c->phase==LH_CP_PUBLISHING) {status=1;goto reply;}
        if (c->phase!=LH_CP_HELD || get32(p+24)!=c->generation) goto reply;
        if ((load(&c->gate)&(CLOSED|INVALID|FAULT|READERS))!=(CLOSED|INVALID)) goto reply;
        c->phase=LH_CP_PUBLISHING;result=LH_CP_APPLY;goto done;
    }
reply:
    response(out,id,op,status,lo,hi,c->generation);
done:
    give(c);return result;
}
lh_u32 lh_cp_published(struct lh_cp *c,lh_u32 id,lh_u32 success,lh_u32 generation,unsigned char *out) {
    if (!take(c)) return LH_CP_DROP;
    lh_u32 result=LH_CP_DROP;
    if (id==c->last_id && c->phase==LH_CP_PUBLISHING) {
        lh_u32 gate=load(&c->gate);
        if ((gate&(CLOSED|INVALID|FAULT|READERS))!=(CLOSED|INVALID)) success=0;
        /* Native descriptor handling can advance its generation even when
         * mapping fails. The caller supplies the observed current generation,
         * so recovery must not retain an obsolete pre-publication value. */
        c->generation=generation;
        if (success) {
            c->phase=LH_CP_COMMITTED;
            __atomic_fetch_and(&c->gate,~(CLOSED|INVALID),__ATOMIC_ACQ_REL);
        } else c->phase=LH_CP_HELD;
        response(out,id,LH_PUBLISH,success?0:2,c->session_lo,c->session_hi,c->generation);
        result=LH_CP_REPLY;
    }
    give(c);return result;
}
