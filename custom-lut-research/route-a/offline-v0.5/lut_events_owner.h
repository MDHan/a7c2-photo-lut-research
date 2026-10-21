#ifndef LUT_EVENTS_OWNER_H
#define LUT_EVENTS_OWNER_H
#include "lut_handoff_ap.h"
typedef unsigned long owner_word;
struct lh_transfer_request {
    const lh_u32 *source,*target;
    lh_u32 length,count;
    void (*callback)(lh_u32,void *);
    void *cookie;
};
struct lh_upload_owner {
    struct lh_ap core;
    lh_u32 lock,fatal,hello;
    int result;
    owner_word thread;
    lh_u32 expected_handle,published;
    unsigned char descriptor[96];
    lh_u32 source[2],target[2];
    struct lh_transfer_request request;
    lh_u32 transfer,ticket,cancel_id;
    owner_word active_task;
    lh_u32 active_lut,system,last_lut,reset_confirmed,task_cancel;
};
_Static_assert(sizeof(struct lh_upload_owner)==248,"owner BSS ABI");
struct lh_upload_owner *lh_owner_context(void);
int lh_owner_run(void *);
lh_u32 lh_owner_cancel_request(lh_u32 id);
lh_u32 lh_owner_receive(struct lh_ap *,const unsigned char *,lh_u32);
void lh_owner_transfer(const lh_u32 *,lh_u32 *);
void lh_owner_publish(lh_u32,const unsigned char *,owner_word,lh_u32,void *,owner_word);
void lh_owner_secondary(const void *,lh_u32 *);
#endif
