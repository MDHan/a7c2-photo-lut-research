/* Central exact-build entry guards cover indirect calls as well as known BLs.
 * Parent leases protect descriptor preparation; accepted messages retain their
 * existing child leases until DMA completion. External inputs carry no epoch,
 * so these guards establish exclusion, not caller intent or allocation origin.
 */
#include "lut_cp_publication.h"
#include "lut_events_native_snapshot.h"
void lut_all_context(u32 owner,const u32 *context) {native_snapshot(owner,context);}

static int all_source(u32 target,const u32 *a,const u32 *b,u32 c,u32 d,u32 e,u32 kind) {
    u32 token=((u32 (*)(struct lh_cp *))CP_READER_BEGIN)(CP);
    if(!token) return -20;
    u32 first[3],second[3];
    for(u32 i=0;i<(kind==2?2U:3U);i++) first[i]=a[i];
    int result;
    if(kind==1) {
        for(u32 i=0;i<3;i++) second[i]=b[i];
        result=((int (*)(const u32 *,const u32 *,u32,u32,u32))target)(first,second,c,d,e);
    } else if(kind==2) result=((int (*)(u32,const u32 *,u32))target)(c,first,d);
    else result=((int (*)(const u32 *,u32,u32,u32))target)(first,c,d,e);
    /* A failure return does not drain already accepted child messages. */
    if(!reader_end(token,0)) quarantine();
    return result;
}
int lut_all_load(const u32 *source,u32 slot,u32 callback,u32 owner) {
    return all_source(LUT_NATIVE_LOAD_ORIGINAL,source,0,slot,callback,owner,0);
}
int lut_all_art(const u32 *source,const u32 *art,u32 slot,u32 callback,u32 owner) {
    return all_source(LUT_NATIVE_ART_ORIGINAL,source,art,slot,callback,owner,1);
}
int lut_all_queue(u32 group,const u32 *source,u32 callback) {
    return all_source(LUT_NATIVE_QUEUE_ORIGINAL,source,0,group,callback,0,2);
}
int lut_all_art_queue(u32 group,const u32 *source,u32 callback) {
    return all_source(LUT_NATIVE_ART_QUEUE_ORIGINAL,source,0,group,callback,0,2);
}
u32 lut_all_publish(const unsigned char *packet) {
    struct lh_cp_publication *r=(struct lh_cp_publication *)CP_PUBLICATION_STATE;
    if(__atomic_load_n(&r->lock,__ATOMIC_ACQUIRE) &&
       __atomic_load_n(&CP->phase,__ATOMIC_ACQUIRE)==LH_CP_PUBLISHING && packet==r->descriptor)
        return ((u32 (*)(const unsigned char *))LUT_NATIVE_PUBLISH_ORIGINAL)(packet);
    /* Internal reapply of the exact confirmed descriptor is an idempotent
     * no-op: never remap or advance generation outside the upload protocol. */
    if(!r->id || !r->success || r->pending || __atomic_load_n(&r->lock,__ATOMIC_ACQUIRE) ||
       __atomic_load_n(&CP->phase,__ATOMIC_ACQUIRE)!=LH_CP_COMMITTED ||
       ((volatile u32 *)0x165a720U)[0xc0/4]!=r->generation) return 0;
    for(u32 i=0;i<96;i++) if(packet[i]!=r->descriptor[i]) return 0;
    return 1;
}
