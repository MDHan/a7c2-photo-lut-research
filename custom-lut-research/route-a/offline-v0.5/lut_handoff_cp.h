#ifndef LUT_HANDOFF_CP_H
#define LUT_HANDOFF_CP_H
#include "lut_handoff_ap.h"
#define LH_CP_READERS 29U
struct lh_cp {
    lh_u32 lock, gate, initialized, session_lo, session_hi;
    lh_u32 last_id, phase, generation, readers[LH_CP_READERS];
};
enum { LH_CP_IDLE=0, LH_CP_WAIT=1, LH_CP_HELD=2, LH_CP_PUBLISHING=3,
       LH_CP_COMMITTED=4, LH_CP_CANCELLED=5 };
enum { LH_CP_NOT_OURS=0, LH_CP_DROP=1, LH_CP_REPLY=2, LH_CP_APPLY=3 };
/* Zero-initialized storage only. Reader records are not reset by open(). */
lh_u32 lh_cp_open(struct lh_cp *, lh_u32, lh_u32, lh_u32);
lh_u32 lh_cp_reader_begin(struct lh_cp *);
lh_u32 lh_cp_reader_end(struct lh_cp *, lh_u32);
lh_u32 lh_cp_reader_fault(struct lh_cp *, lh_u32);
/* Private requests never invoke native code or send while holding the lock.
 * APPLY requires applying the new descriptor outside this function, keeping
 * the gate closed, then calling published with verified completion status.
 * DROP includes contention; a caller may retry without spinning in an ISR.
 */
lh_u32 lh_cp_request(struct lh_cp *, const unsigned char *, lh_u32, unsigned char *);
/* generation is the observed current native descriptor generation, including
 * failure paths that already advanced it. success requires validated data. */
lh_u32 lh_cp_published(struct lh_cp *, lh_u32, lh_u32, lh_u32, unsigned char *);
#endif
