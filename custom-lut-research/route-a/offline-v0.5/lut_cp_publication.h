#ifndef LUT_CP_PUBLICATION_H
#define LUT_CP_PUBLICATION_H
#include "lut_handoff_cp.h"
/* Zero-initialized, single receiver state; no runtime force-reset operation.
 * A descriptor is retained to reject a changed payload reusing a transaction
 * ID, and to finish publication after transient core-lock contention. */
struct lh_cp_publication {
    lh_u32 lock,pending,id,success,generation;
    unsigned char descriptor[96];
};
/* ACQUIRE/CANCEL: existing 32-byte private request.
 * PUBLISH: that same header followed by the exact 96-byte native descriptor.
 * The header and descriptor must be sent as one 128-byte message.
 * Returns NOT_OURS, DROP or REPLY; never exposes APPLY to a coordinator.
 * Caller owns an immutable input of n bytes and >=32 writable output bytes.
 * Native/legacy 4155 packets are deliberately consumed without publication:
 * this component cannot be enabled before the AP uploader is migrated. */
lh_u32 lh_cp_receive_publication(struct lh_cp *,struct lh_cp_publication *,
                               const unsigned char *,lh_u32,unsigned char *);
#endif
