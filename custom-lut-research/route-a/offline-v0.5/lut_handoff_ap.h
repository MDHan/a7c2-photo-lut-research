#ifndef LUT_HANDOFF_AP_H
#define LUT_HANDOFF_AP_H
typedef unsigned int lh_u32;
struct lh_ap { lh_u32 control, session_lo, session_hi, generation; };
enum { LH_IDLE=1, LH_WAIT=2, LH_UPDATE=3, LH_READY=4, LH_WRITE=5,
       LH_COMMIT=6, LH_ABORT=7 };
enum { LH_ACQUIRE=1, LH_PUBLISH=2, LH_CANCEL=3 };
/* New private wire contract. Not an existing native LUT command extension.
 * 32 bytes LE: type, flags, command16, id32, magic32, version16, op8,
 * status8, session64, generation32, reserved32.
 * Only a future CP peer that implements the reader/write lease may grant.
 */
enum { LH_WIRE_SIZE=32, LH_MAGIC=0x504c5554, LH_COMMAND=0x4155 };
lh_u32 lh_ap_open(struct lh_ap *, lh_u32, lh_u32);
lh_u32 lh_ap_begin(struct lh_ap *);
lh_u32 lh_ap_write(struct lh_ap *, lh_u32);
lh_u32 lh_ap_written(struct lh_ap *, lh_u32, lh_u32);
lh_u32 lh_ap_cancel(struct lh_ap *, lh_u32);
lh_u32 lh_ap_request(struct lh_ap *, unsigned char *);
/* Returns 1 for an owned private reply, including malformed/stale replies.
 * No allocation, send, blocking lock, wait or pointer retention.
 */
lh_u32 lh_ap_receive(struct lh_ap *, const unsigned char *, lh_u32);
#endif
