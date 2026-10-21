#include "lut_handoff_ap.h"
#define INLINE static __attribute__((always_inline)) inline
#define PHASE 15U
#define LAST_ID 0x0fffffffU
_Static_assert(sizeof(struct lh_ap)==16, "AP BSS contract");
INLINE lh_u32 read_control(struct lh_ap *c) {
    return __atomic_load_n(&c->control,__ATOMIC_ACQUIRE);
}
INLINE lh_u32 change(struct lh_ap *c, lh_u32 *old, lh_u32 next) {
    return __atomic_compare_exchange_n(&c->control,old,next,0,
                                       __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
}
INLINE lh_u32 get32(const unsigned char *p) {
    return (lh_u32)p[0]|((lh_u32)p[1]<<8)|((lh_u32)p[2]<<16)|((lh_u32)p[3]<<24);
}
INLINE void put32(unsigned char *p, lh_u32 value) {
    p[0]=value; p[1]=value>>8; p[2]=value>>16; p[3]=value>>24;
}
lh_u32 lh_ap_open(struct lh_ap *c, lh_u32 lo, lh_u32 hi) {
    lh_u32 old=0;
    if (!(lo|hi) || !change(c,&old,LH_UPDATE)) return 0;
    c->session_lo=lo; c->session_hi=hi;
    __atomic_store_n(&c->generation,0,__ATOMIC_RELAXED);
    __atomic_store_n(&c->control,LH_IDLE,__ATOMIC_RELEASE);
    return 1;
}
lh_u32 lh_ap_begin(struct lh_ap *c) {
    lh_u32 old=read_control(c);
    for (;;) {
        if ((old&PHASE)!=LH_IDLE || (old>>4)==LAST_ID) return 0;
        lh_u32 id=(old>>4)+1;
        if (change(c,&old,(id<<4)|LH_WAIT)) return id;
    }
}
lh_u32 lh_ap_write(struct lh_ap *c, lh_u32 id) {
    if (!id || id>LAST_ID) return 0;
    lh_u32 old=(id<<4)|LH_READY;
    return change(c,&old,(id<<4)|LH_WRITE);
}
lh_u32 lh_ap_written(struct lh_ap *c, lh_u32 id, lh_u32 success) {
    if (!id || id>LAST_ID) return 0;
    lh_u32 old=(id<<4)|LH_WRITE;
    return change(c,&old,(id<<4)|(success?LH_COMMIT:LH_ABORT));
}
lh_u32 lh_ap_cancel(struct lh_ap *c, lh_u32 id) {
    if (!id || id>LAST_ID) return 0;
    lh_u32 old=read_control(c);
    for (;;) {
        if ((old>>4)!=id) return 0;
        lh_u32 phase=old&PHASE;
        if (phase==LH_ABORT) return 1;
        /* Never cancel a copy/DMA still in progress. Its owner must first
         * establish quiescence then call written(..., 0). UPDATE is transient;
         * the caller must retry, not reset this cell. */
        if (phase!=LH_WAIT && phase!=LH_READY && phase!=LH_COMMIT) return 0;
        if (change(c,&old,(id<<4)|LH_ABORT)) return 1;
    }
}
lh_u32 lh_ap_request(struct lh_ap *c, unsigned char *out) {
    lh_u32 old=read_control(c), phase=old&PHASE, op;
    if (!(old>>4)) return 0;
    if (phase==LH_WAIT) op=LH_ACQUIRE;
    else if (phase==LH_COMMIT) op=LH_PUBLISH;
    else if (phase==LH_ABORT) op=LH_CANCEL;
    else return 0;
    put32(out,((lh_u32)LH_COMMAND<<16)|5U);
    put32(out+4,old>>4); put32(out+8,LH_MAGIC);
    put32(out+12,1U|(op<<16));
    put32(out+16,c->session_lo); put32(out+20,c->session_hi);
    put32(out+24,__atomic_load_n(&c->generation,__ATOMIC_RELAXED));
    put32(out+28,0);
    /* A single upload owner must serialize request construction and sends.
     * This check detects concurrent receive changes, not a send-time lock. */
    return read_control(c)==old ? LH_WIRE_SIZE : 0;
}
lh_u32 lh_ap_receive(struct lh_ap *c, const unsigned char *p, lh_u32 n) {
    if (n<12 || p[0]!=1 || p[2]!=0x55 || p[3]!=0x41 || get32(p+8)!=LH_MAGIC)
        return 0;
    if (n!=LH_WIRE_SIZE || p[1] || p[12]!=1 || p[13] || p[15]>2 || get32(p+28))
        return 1;
    lh_u32 old=read_control(c), id=get32(p+4), op=p[14], status=p[15];
    if (!(old>>4) || id!=(old>>4) || get32(p+16)!=c->session_lo ||
        get32(p+20)!=c->session_hi) return 1;
    for (;;) {
        if ((old>>4)!=id) return 1;
        lh_u32 phase=old&PHASE, next;
        if (op==LH_ACQUIRE && phase==LH_WAIT) {
            if (status==1) return 1; /* busy: retry or explicitly cancel */
            next=status?LH_ABORT:LH_UPDATE;
        } else if (op==LH_PUBLISH && phase==LH_COMMIT) {
            next=status?LH_ABORT:LH_IDLE;
        } else if (op==LH_CANCEL && phase==LH_ABORT) {
            if (status) return 1; /* retain quarantine until closure confirmed */
            next=LH_IDLE;
        } else return 1;
        if (!change(c,&old,(id<<4)|next)) continue;
        if (next==LH_UPDATE) {
            __atomic_store_n(&c->generation,get32(p+24),__ATOMIC_RELAXED);
            __atomic_store_n(&c->control,(id<<4)|LH_READY,__ATOMIC_RELEASE);
        }
        return 1;
    }
}
