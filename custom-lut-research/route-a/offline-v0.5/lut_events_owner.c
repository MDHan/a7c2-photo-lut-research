#include "lut_events_owner.h"
#define INLINE static __attribute__((always_inline)) inline
#define TIMEOUT 5000UL
#define PENDING 1U
#define DONE 2U
extern int lh_native_allocate(lh_u32,void **,lh_u32,lh_u32);
extern void lh_native_source(void *,lh_u32);
extern int lh_native_send(lh_u32,void *);
extern int lh_native_free(lh_u32,void *);
extern void *lh_native_copy(void *,const void *,owner_word);
extern int lh_native_open(const char *,int);
extern long lh_native_read(int,void *,owner_word);
extern int lh_native_close(int);
extern owner_word lh_native_self(void);
extern int lh_native_sleep(unsigned int);
extern int lh_native_interchip(struct lh_transfer_request *);
extern int lh_copy_original(const void *);
extern int lh_native_load(lh_u32,lh_u32,lh_u32 *,lh_u32 *);
extern int lh_native_describe(lh_u32,lh_u32,lh_u32,lh_u32,const void *);
extern void lh_native_message(const void *,lh_u32 *);
extern void lh_native_secondary(const void *,lh_u32 *);
extern long lh_monotonic(long *);
INLINE lh_u32 load(lh_u32 *p) {return __atomic_load_n(p,__ATOMIC_ACQUIRE);}
INLINE lh_u32 phase(struct lh_upload_owner *o) {return load(&o->core.control)&15;}
INLINE lh_u32 transfer_phase(struct lh_upload_owner *o) {return load(&o->transfer)&3;}
INLINE int owns(struct lh_upload_owner *o) {return load(&o->lock) && __atomic_load_n(&o->thread,__ATOMIC_ACQUIRE)==lh_native_self();}
INLINE lh_u32 get32(const unsigned char *p) {
    return (lh_u32)p[0]|(lh_u32)p[1]<<8|(lh_u32)p[2]<<16|(lh_u32)p[3]<<24;
}
static int now(owner_word *out) {
    long t[2];
    if(lh_monotonic(t) || t[0]<0 || t[0]>0x3fffffffffffffL || t[1]<0 || t[1]>=1000000000L) return 0;
    *out=(owner_word)t[0]*1000+(owner_word)t[1]/1000000;return 1;
}
/* Results: 0 accepted, 1 retry without changing protocol state, 2 stop.
 * A failed free is retained as a fatal owner condition; never auto-retry. */
static int send_bytes(const void *packet,lh_u32 size) {
    void *message=0;
    if(lh_native_allocate(0x90030001U,&message,size,1)) return 1;
    if(!message) return 2;
    lh_native_source(message,0x80020002U);
    lh_native_copy(message,packet,size);
    if(!lh_native_send(0x90030001U,message)) return 0;
    return lh_native_free(0x90030001U,message)?2:1;
}
static int send_current(struct lh_upload_owner *o,int hello) {
    lh_u32 packet[32],n=32;
    if(hello) {
        packet[0]=0x41550005U;packet[1]=0;packet[2]=LH_MAGIC;packet[3]=0x40001;
        packet[4]=o->core.session_lo;packet[5]=o->core.session_hi;packet[6]=packet[7]=0;
    } else {
        n=lh_ap_request(&o->core,(unsigned char *)packet);
        if(!n) return 1; /* receive may be publishing READY/IDLE concurrently */
        if(((unsigned char *)packet)[14]==LH_PUBLISH) {
            lh_native_copy((unsigned char *)packet+32,o->descriptor,96);n=128;
        }
    }
    return send_bytes(packet,n);
}
static int pump(struct lh_upload_owner *o,lh_u32 target,int hello) {
    owner_word start,t;
    if(!now(&start)) return 0;
    for(lh_u32 i=0;i<1024;i++) {
        if(hello && load(&o->task_cancel)) return 0;
        if(hello?load(&o->hello)==1:phase(o)==target) return 1;
        if(!hello && (phase(o)==LH_WAIT || phase(o)==LH_READY || phase(o)==LH_COMMIT) &&
           (load(&o->task_cancel) || load(&o->cancel_id)==load(&o->core.control)>>4)) return 0;
        if(o->fatal || (hello && load(&o->hello)==2) || (!hello && target==LH_READY && phase(o)==LH_ABORT)) return 0;
        if(!now(&t) || t<start || t-start>=TIMEOUT) return 0;
        if(send_current(o,hello)==2) {o->fatal=1;return 0;}
        lh_native_sleep(10000);
    }
    return 0;
}
static int bootstrap(struct lh_upload_owner *o) {
    if(!load(&o->core.control)) {
        lh_u32 identity[2]={0,0};unsigned char *p=(unsigned char *)identity;
        int fd=lh_native_open("/dev/urandom",0);if(fd<0) return 0;
        lh_u32 used=0;
        for(lh_u32 tries=0;tries<8 && used<8;tries++) {
            long n=lh_native_read(fd,p+used,8-used);
            if(n<=0 || (owner_word)n>8-used) break;
            used+=(lh_u32)n;
        }
        int closed=lh_native_close(fd);
        if(closed) {o->fatal=1;return 0;}
        if(used!=8 || !(identity[0]|identity[1]) || !lh_ap_open(&o->core,identity[0],identity[1])) return 0;
    }
    __atomic_store_n(&o->hello,0,__ATOMIC_RELEASE);
    return pump(o,0,1); /* Revalidate the immutable session before each task. */
}
lh_u32 lh_owner_receive(struct lh_ap *core,const unsigned char *p,lh_u32 n) {
    struct lh_upload_owner *o=(struct lh_upload_owner *)core;
    if(n==32 && p[0]==1 && !p[1] && p[2]==0x55 && p[3]==0x41 && get32(p+8)==LH_MAGIC &&
       p[12]==1 && !p[13] && p[14]==LH_PUBLISH && !p[15] && !get32(p+28)) {
        lh_u32 control=load(&core->control);
        if((control&15)==LH_COMMIT && get32(p+4)==control>>4 &&
           get32(p+16)==core->session_lo && get32(p+20)==core->session_hi)
            __atomic_store_n(&o->published,1,__ATOMIC_RELEASE);
    }
    if(n==32 && p[0]==1 && !p[1] && p[2]==0x55 && p[3]==0x41 && get32(p+8)==LH_MAGIC &&
       p[12]==1 && !p[13] && p[14]==LH_CANCEL && !p[15] && get32(p+28)==1) {
        lh_u32 control=load(&core->control);
        if((control&15)==LH_ABORT && get32(p+4)==control>>4 &&
           get32(p+16)==core->session_lo && get32(p+20)==core->session_hi) {
            unsigned char ordinary[32];
            for(lh_u32 i=0;i<32;i++) ordinary[i]=p[i];
            ordinary[28]=0;
            __atomic_store_n(&o->published,1,__ATOMIC_RELEASE);
            return lh_ap_receive(core,ordinary,32);
        }
        return 1;
    }
    if(n>=16 && p[0]==1 && p[2]==0x55 && p[3]==0x41 && get32(p+8)==LH_MAGIC && p[14]==4) {
        if(n==32 && !p[1] && !get32(p+4) && p[12]==1 && !p[13] && p[15]<=2 && !get32(p+24) && !get32(p+28) &&
           (core->session_lo|core->session_hi) && get32(p+16)==core->session_lo && get32(p+20)==core->session_hi)
            __atomic_store_n(&o->hello,p[15]?2:1,__ATOMIC_RELEASE);
        return 1;
    }
    return lh_ap_receive(core,p,n);
}
int lh_owner_copy(const void *record) {
    struct lh_upload_owner *o=lh_owner_context();
    if(!owns(o) || phase(o)!=LH_WRITE || (load(&o->task_cancel) || load(&o->cancel_id)==load(&o->core.control)>>4)) return 0;
    return lh_copy_original(record);
}
static void transfer_done(lh_u32 opaque,void *cookie) {
    (void)opaque;struct lh_upload_owner *o=lh_owner_context();
    owner_word nonce=((owner_word)o->core.session_hi<<32)|o->core.session_lo;
    owner_word ticket=(owner_word)cookie-nonce;
    if(!ticket || ticket>0x3fffffffU) return;
    lh_u32 pending=((lh_u32)ticket<<2)|PENDING;
    __atomic_compare_exchange_n(&o->transfer,&pending,(pending&~3U)|DONE,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
}
static int wait_transfer(struct lh_upload_owner *o,int cancellable) {
    owner_word start,t;if(!now(&start)) return 0;
    for(lh_u32 i=0;i<1024;i++) {
        if(transfer_phase(o)==DONE) return 1;
        if(cancellable && (load(&o->task_cancel) || load(&o->cancel_id)==load(&o->core.control)>>4)) return 0;
        if(!now(&t) || t<start || t-start>=TIMEOUT) return 0;
        lh_native_sleep(10000);
    }
    return 0;
}
void lh_owner_transfer(const lh_u32 *input,lh_u32 *result) {
    struct lh_upload_owner *o=lh_owner_context();*result=2;
    if(!owns(o) || phase(o)!=LH_WRITE || transfer_phase(o)==PENDING) return;
    o->source[0]=input[0];o->source[1]=input[1];o->target[0]=input[2];o->target[1]=input[3];
    if(o->ticket==0x3fffffffU) {o->fatal=1;return;}
    lh_u32 ticket=++o->ticket;
    owner_word nonce=((owner_word)o->core.session_hi<<32)|o->core.session_lo;
    o->request=(struct lh_transfer_request){o->source,o->target,input[4],1,transfer_done,(void *)(nonce+ticket)};
    __atomic_store_n(&o->transfer,(ticket<<2)|PENDING,__ATOMIC_RELEASE);
    int submitted=lh_native_interchip(&o->request);
    if(submitted) {
        /* Same rejection contract as the native wrapper: nonzero submission
         * result is rejected, not an outstanding operation. */
        __atomic_store_n(&o->transfer,0,__ATOMIC_RELEASE);return;
    }
    if(wait_transfer(o,1) && load(&o->cancel_id)!=(load(&o->core.control)>>4)) *result=0;
    /* Timeout retains PENDING and a persistent cookie. No callback can write
     * into the native caller's stack after this function returns. */
}
static int cancel(struct lh_upload_owner *o) {
    lh_u32 id=load(&o->core.control)>>4;
    for(lh_u32 i=0;i<8;i++) {
        if(phase(o)==LH_IDLE) return 1;
        if(lh_ap_cancel(&o->core,id)) return pump(o,LH_IDLE,0);
        lh_native_sleep(10000);
    }
    return 0;
}
void lh_owner_publish(lh_u32 port,const unsigned char *packet,owner_word n,lh_u32 key,void *reply,owner_word reply_n) {
    (void)key;(void)reply;(void)reply_n;
    struct lh_upload_owner *o=lh_owner_context();
    if(!owns(o) || phase(o)!=LH_COMMIT || port!=0x90030001U || n!=96 || get32(packet)!=0x41550005U ||
       get32(packet+12)!=(o->expected_handle?o->expected_handle:0xffffffffU)) return;
    lh_native_copy(o->descriptor,packet,96);
    if(!o->expected_handle) for(lh_u32 i=16;i<32;i++) o->descriptor[i]=0;
    if(!pump(o,LH_IDLE,0)) cancel(o);
}
void lh_owner_secondary(const void *record,lh_u32 *result) {
    struct lh_upload_owner *o=lh_owner_context();
    if(owns(o) && load(&o->published) && phase(o)==LH_IDLE) lh_native_secondary(record,result);
    else *result=2;
}
lh_u32 lh_owner_cancel_request(lh_u32 id) {
    struct lh_upload_owner *o=lh_owner_context();lh_u32 control=load(&o->core.control);
    if(!id || id!=(control>>4) || (control&15)==LH_IDLE) return 0;
    __atomic_store_n(&o->cancel_id,id,__ATOMIC_RELEASE);
    lh_ap_cancel(&o->core,id); /* WRITE is retained until its transfer drains. */
    return 1;
}
int lh_owner_run(void *task) {
    struct lh_upload_owner *o=lh_owner_context();lh_u32 zero=0;
    if(!__atomic_compare_exchange_n(&o->lock,&zero,1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) return 1;
    __atomic_store_n(&o->thread,lh_native_self(),__ATOMIC_RELEASE);__atomic_store_n(&o->task_cancel,0,__ATOMIC_RELEASE);
    __atomic_store_n(&o->active_lut,((lh_u32 *)task)[0x18/4],__ATOMIC_RELEASE);o->system=((lh_u32 *)task)[0x14/4];
    __atomic_store_n(&o->active_task,(owner_word)task,__ATOMIC_RELEASE);int error=-16;
    if(o->fatal || !bootstrap(o)) {if(load(&o->task_cancel)) error=-125;goto done;}
    if(load(&o->task_cancel)) {error=-125;goto done;}
    if(phase(o)==LH_WRITE) {
        if(transfer_phase(o)!=DONE && !wait_transfer(o,0)) goto done;
        if(!lh_ap_written(&o->core,load(&o->core.control)>>4,0)) goto done;
    }
    if(phase(o)!=LH_IDLE && !cancel(o)) goto done;
    lh_u32 id=lh_ap_begin(&o->core);if(!id) goto done;
    if(!pump(o,LH_READY,0)) {cancel(o);error=(load(&o->task_cancel) || load(&o->cancel_id)==id)?-125:-110;goto done;}
    if(!lh_ap_write(&o->core,id)) {cancel(o);goto done;}
    __atomic_store_n(&o->published,0,__ATOMIC_RELEASE);__atomic_store_n(&o->transfer,0,__ATOMIC_RELEASE);
    lh_u32 *words=task,handle=0,length=0,lut=words[0x18/4],exists=words[0x6c/4];
    if(lut>18) {lh_ap_written(&o->core,id,0);cancel(o);error=-22;goto done;}
    int loaded=lh_native_load(lut,exists,&handle,&length);
    if(transfer_phase(o)==PENDING) {error=(load(&o->task_cancel) || load(&o->cancel_id)==id)?-125:-110;goto done;}
    if(!loaded || (exists && lut>=3 && !handle)) {
        lh_ap_written(&o->core,id,0);cancel(o);error=(load(&o->task_cancel) || load(&o->cancel_id)==id)?-125:-5;goto done;
    }
    o->expected_handle=handle;
    if(!lh_ap_written(&o->core,id,1)) goto done;
    if(lut>=3) lh_native_describe(words[0x14/4],lut,handle,length,(unsigned char *)task+0x2c);
    else {
        struct {lh_u32 system,profile,handle,offset,length,art_offset,art_length;unsigned char raw[64];lh_u32 art;} record={0};
        record.system=words[0x14/4];record.profile=0x62a;
        lh_native_copy(record.raw,(unsigned char *)task+0x2c,64);
        lh_u32 result=2,secondary[7]={lut,0,0,0,0,0,0};
        lh_native_message(&record,&result);lh_owner_secondary(secondary,&result);
    }
    if(!load(&o->published)) {cancel(o);error=(load(&o->task_cancel) || load(&o->cancel_id)==id)?-125:-110;goto done;}
    o->last_lut=handle?lut:0;error=0;
done:
    o->result=error;__atomic_store_n(&o->thread,0,__ATOMIC_RELEASE);
    __atomic_store_n(&o->active_task,0,__ATOMIC_RELEASE);
    __atomic_store_n(&o->lock,0,__ATOMIC_RELEASE);
    return 1; /* Native sequence worker ignores this run return value. */
}

extern int lh_delete_original(lh_u32);
extern int lh_delete_cube_original(lh_u32);
extern void lh_reset_original(void *);

/* Native task replacement/cancel virtual slot. Never infer cancellation from
 * a destructor or mark an unrelated task identity as cancelled. */
void lh_menu_cancel(void *task) {
    struct lh_upload_owner *o=lh_owner_context();
    if(task && __atomic_load_n(&o->active_task,__ATOMIC_ACQUIRE)==(owner_word)task) {
        __atomic_store_n(&o->task_cancel,1,__ATOMIC_RELEASE);
        lh_owner_cancel_request(load(&o->core.control)>>4);
    }
}
static int menu_lock(struct lh_upload_owner *o,lh_u32 slot) {
    owner_word start,t;if(!now(&start)) return 0;
    for(lh_u32 i=0;i<1024;i++) {
        lh_u32 zero=0;
        if(__atomic_compare_exchange_n(&o->lock,&zero,1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
            __atomic_store_n(&o->thread,lh_native_self(),__ATOMIC_RELEASE);__atomic_store_n(&o->task_cancel,0,__ATOMIC_RELEASE);return 1;
        }
        if(load(&o->active_lut)==slot+3) lh_owner_cancel_request(load(&o->core.control)>>4);
        if(!now(&t) || t<start || t-start>=TIMEOUT) return 0;
        lh_native_sleep(10000);
    }
    return 0;
}
static void menu_unlock(struct lh_upload_owner *o) {
    __atomic_store_n(&o->thread,0,__ATOMIC_RELEASE);__atomic_store_n(&o->lock,0,__ATOMIC_RELEASE);
}
static int menu_recover(struct lh_upload_owner *o) {
    if(o->fatal || !bootstrap(o)) return 0;
    if(phase(o)==LH_WRITE) {
        if(transfer_phase(o)!=DONE && !wait_transfer(o,0)) return 0;
        if(!lh_ap_written(&o->core,load(&o->core.control)>>4,0)) return 0;
    }
    return phase(o)==LH_IDLE || cancel(o);
}
static int menu_clear(struct lh_upload_owner *o) {
    lh_u32 id=lh_ap_begin(&o->core);
    if(!id || !pump(o,LH_READY,0) || !lh_ap_write(&o->core,id)) {cancel(o);return 0;}
    __atomic_store_n(&o->published,0,__ATOMIC_RELEASE);o->expected_handle=0;
    if(!lh_ap_written(&o->core,id,1)) return 0;
    lh_u32 packet[24]={0x41550005U,0,0x62a,0xffffffffU};
    lh_owner_publish(0x90030001U,(const unsigned char *)packet,96,0,0,0);
    if(!load(&o->published)) {cancel(o);return 0;}
    o->last_lut=0;return 1;
}
int lh_menu_delete(lh_u32 slot) {
    struct lh_upload_owner *o=lh_owner_context();
    if(slot>49 || !menu_lock(o,slot)) return 3;
    int result=3;
    if(menu_recover(o) && (o->last_lut!=slot+3 || menu_clear(o))) result=lh_delete_original(slot);
    o->result=result? -16:0;menu_unlock(o);return result;
}
int lh_menu_delete_cube(lh_u32 slot) {
    struct lh_upload_owner *o=lh_owner_context();
    if(slot>49 || !menu_lock(o,slot)) return 3;
    int result=3;
    if(menu_recover(o)) result=lh_delete_cube_original(slot);
    o->result=result? -16:0;menu_unlock(o);return result;
}
void lh_menu_reset(void *task) {
    struct lh_upload_owner *o=lh_owner_context();lh_u32 *words=task;
    lh_u32 selected=words[0x18/4],deleted=words[0x1c/4];
    if(!menu_lock(o,deleted>=3?deleted-3:50)) return;
    int ok=menu_recover(o) && (selected!=deleted || menu_clear(o));
    if(ok) {
        /* Protocol publication has already completed. The native helper's
         * legacy clear call is deliberately suppressed by its exact hook. */
        o->reset_confirmed=1;lh_reset_original(task);o->reset_confirmed=0;
    }
    o->result=ok?0:-16;menu_unlock(o);
}
void lh_menu_reset_legacy(const void *record,lh_u32 *result) {
    (void)record;struct lh_upload_owner *o=lh_owner_context();
    *result=(owns(o) && o->reset_confirmed)?0:2;
}
