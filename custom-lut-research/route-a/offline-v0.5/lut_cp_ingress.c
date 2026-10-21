#include "lut_cp_publication.h"
#ifndef CP_PUBLICATION_ENTRY
#include "lifecycle-dev/cp-ingress-build/layout.h"
#endif

/* Called only from the native type-5 queue dispatch, before its unlock/free.
 * The native size helper reads the allocator's requested payload length.
 * Publication retains its own descriptor; reply transport copies before return.
 * Code/state addresses are supplied by the composition, not packet contents. */
lh_u32 lh_cp_ingress(const unsigned char *packet, lh_u32 source_port) {
    typedef lh_u32 (*length_fn)(const unsigned char *);
    lh_u32 n=((length_fn)0xbec28fU)(packet);
    if(n<4 || n>4096) return 1;
    unsigned char reply[32];
    typedef lh_u32 (*receive_fn)(struct lh_cp *,struct lh_cp_publication *,
                                const unsigned char *,lh_u32,unsigned char *);
    lh_u32 result=((receive_fn)CP_PUBLICATION_ENTRY)(
        (struct lh_cp *)CP_STATE,(struct lh_cp_publication *)CP_PUBLICATION_STATE,
        packet,n,reply);
    if(result==LH_CP_NOT_OURS)
        return ((lh_u32 (*)(const unsigned char *,lh_u32))0x35cf71U)(packet,source_port);
    if(result==LH_CP_REPLY) {
        /* A failed send is not a successful transaction at the AP. Keep CP's
         * completed state so a retry can obtain the same result without publish. */
        ((lh_u32 (*)(const unsigned char *,lh_u32,lh_u32))0x4b3c49U)(reply,32,source_port);
    }
    return 1;
}
