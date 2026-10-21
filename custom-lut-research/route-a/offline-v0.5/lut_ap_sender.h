#ifndef LUT_AP_SENDER_H
#define LUT_AP_SENDER_H
#include "lut_handoff_ap.h"
enum { LH_SEND_ACCEPTED=0, LH_SEND_RETRY=1, LH_SEND_STOP=2 };
/* One upload owner serializes this call with begin/write/cancel and descriptor
 * construction. ACCEPTED is transport acceptance, never a publication ack.
 * STOP requires owner intervention; do not retry an uncertain failed free.
 * The descriptor is required only in COMMIT and must remain valid for this call.
 */
lh_u32 lh_ap_send_request(struct lh_ap *, const unsigned char *descriptor);
#endif
