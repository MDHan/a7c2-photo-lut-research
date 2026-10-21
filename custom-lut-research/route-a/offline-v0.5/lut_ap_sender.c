#include "lut_ap_sender.h"
/* Exact native AP services. The builder resolves relative calls to the real
 * import veneers; no absolute runtime pointers, heap caches or retained packet. */
extern int lh_native_allocate(lh_u32,void **,lh_u32,lh_u32);
extern void lh_native_source(void *,lh_u32);
extern int lh_native_send(lh_u32,void *);
extern int lh_native_free(lh_u32,void *);
extern void *lh_native_copy(void *,const void *,unsigned long);

lh_u32 lh_ap_send_request(struct lh_ap *state,const unsigned char *descriptor) {
    unsigned char packet[128];
    lh_u32 n=lh_ap_request(state,packet);
    if(n!=LH_WIRE_SIZE) return LH_SEND_STOP;
    if(packet[14]==LH_PUBLISH) {
        if(!descriptor) return LH_SEND_STOP;
        lh_native_copy(packet+LH_WIRE_SIZE,descriptor,96);
        n+=96;
    }
    void *message=0;
    if(lh_native_allocate(0x90030001U,&message,n,1)) return LH_SEND_RETRY;
    if(!message) return LH_SEND_STOP;
    lh_native_source(message,0x80020002U);
    lh_native_copy(message,packet,n);
    if(!lh_native_send(0x90030001U,message)) return LH_SEND_ACCEPTED;
    return lh_native_free(0x90030001U,message)?LH_SEND_STOP:LH_SEND_RETRY;
}
