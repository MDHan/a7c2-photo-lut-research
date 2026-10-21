#include "lut_cp_publication.h"
#include "lifecycle-dev/cp-publication-build/layout.h"
#define INLINE static __attribute__((always_inline)) inline
#define G ((volatile lh_u32 *)0x165a720U)
_Static_assert(sizeof(struct lh_cp_publication)==116,"publication state ABI");
INLINE lh_u32 get32(const unsigned char *p) {
    return (lh_u32)p[0]|((lh_u32)p[1]<<8)|((lh_u32)p[2]<<16)|((lh_u32)p[3]<<24);
}
INLINE lh_u32 native_valid(const unsigned char *p) {
    lh_u32 offset=get32(p+16),art=get32(p+28);
    return get32(p)==0x41550005U && get32(p+8) && get32(p+12)!=0xffffffffU &&
           get32(p+20)==48000 && (art==0 || art==124) &&
           offset<=0xffffffffU-48000-art &&
           get32(p+24)==(art?offset+48000:0);
}
INLINE lh_u32 finish(struct lh_cp *c,struct lh_cp_publication *r,unsigned char *out) {
    typedef lh_u32 (*published)(struct lh_cp *,lh_u32,lh_u32,lh_u32,unsigned char *);
    lh_u32 result=((published)CP_PUBLISHED)(c,r->id,r->success,r->generation,out);
    if(result==LH_CP_REPLY) r->pending=0;
    return result;
}
lh_u32 lh_cp_receive_publication(struct lh_cp *c,struct lh_cp_publication *r,
                                const unsigned char *p,lh_u32 n,unsigned char *out) {
    if(n<4 || p[0]!=5 || p[2]!=0x55 || p[3]!=0x41) return LH_CP_NOT_OURS;
    if(n<16 || get32(p+8)!=LH_MAGIC) return LH_CP_DROP;
    lh_u32 publish=p[14]==LH_PUBLISH;
    if(n!=(publish?128U:32U) || (publish && !native_valid(p+32))) return LH_CP_DROP;
    lh_u32 zero=0;
    if(!__atomic_compare_exchange_n(&r->lock,&zero,1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return LH_CP_DROP;
    lh_u32 result=LH_CP_DROP,id=get32(p+4);
    /* Complete once, then let the current request generate its own reply.
     * A cancellation after a lost commit reply can therefore still finish. */
    if(r->pending && finish(c,r,out)!=LH_CP_REPLY) goto done;
    if(publish && id==r->id) {
        for(lh_u32 i=0;i<96;i++) if(p[32+i]!=r->descriptor[i]) goto done;
    }
    typedef lh_u32 (*request)(struct lh_cp *,const unsigned char *,lh_u32,unsigned char *);
    result=((request)CP_REQUEST)(c,p,32,out);
    if(result==LH_CP_APPLY) {
        for(lh_u32 i=0;i<96;i++) r->descriptor[i]=p[32+i];
        r->id=id;
        lh_u32 generation=G[0xc0/4];
        ((lh_u32 (*)(const unsigned char *))0x35c54dU)(r->descriptor);
        lh_u32 lo=G[0x68/4],hi=G[0x6c/4],art=get32(r->descriptor+28);
        r->generation=G[0xc0/4];
        r->success=r->generation==generation+1 && (lo|hi) &&
                   G[0x78/4]==48000 && G[0x7c/4]==art;
        if(art) r->success=r->success && G[0x70/4]==lo+48000 &&
                          G[0x74/4]==hi+(lo>0xffffffffU-48000);
        r->pending=1;
        result=finish(c,r,out);
    }
done:
    __atomic_store_n(&r->lock,0,__ATOMIC_RELEASE);
    return result;
}
