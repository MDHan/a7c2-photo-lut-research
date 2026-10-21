#include "pair_core.h"
/* Reuse the existing workspace SHA-256 implementation unchanged. */
typedef lp_u32 u32;
typedef lp_u64 u64;
typedef lp_u8 u8;
#include "sha256.h"
_Static_assert(sizeof(struct lp_report)==208, "fixed native report ABI");
_Static_assert(sizeof(struct lp_stat)==40, "portable stat ABI");

static int equal(const u8 *a, const u8 *b, u32 n) {
    for (u32 i=0; i<n; i++) if (a[i]!=b[i]) return 0;
    return 1;
}
static void clear(void *p, u32 n) {
    for (u32 i=0; i<n; i++) ((u8 *)p)[i]=0;
}
static lp_i64 transfer(const struct lp_io *io, lp_i64 fd, void *data,
                       u32 n, u64 offset, int writing) {
    u32 done=0, interrupted=0;
    while (done<n) {
        lp_i64 result=writing ? io->write(io->context,fd,(u8 *)data+done,n-done,offset+done)
                              : io->read(io->context,fd,(u8 *)data+done,n-done,offset+done);
        if (result==-4 && interrupted++<3) continue;
        if (result<=0 || (u64)result>n-done) return result<0 ? result : -5;
        done+=(u32)result;
    }
    return 0;
}
static lp_i64 hash(const struct lp_plan *p, const struct lp_io *io,
                   struct lp_workspace *w, u32 file, u8 out[32]) {
    SHA256 s; sha_init(&s);
    for (u64 at=0; at<p->size[file];) {
        u64 left=p->size[file]-at;
        u32 n=left>sizeof(w->buffer) ? sizeof(w->buffer) : (u32)left;
        lp_i64 rc=transfer(io,w->fd[file],w->buffer,n,at,0);
        if (rc) return rc;
        sha_add(&s,w->buffer,n); at+=n;
    }
    lp_i64 rc=io->read(io->context,w->fd[file],w->buffer,1,p->size[file]);
    if (rc) return rc<0 ? rc : -27;
    sha_end(&s,out); return 0;
}
static lp_i64 verify(const struct lp_plan *p, const struct lp_io *io,
                     struct lp_workspace *w, int after, u8 out[2][32]) {
    for (u32 file=0; file<2; file++) {
        lp_i64 rc=hash(p,io,w,file,out[file]);
        if (rc) return rc;
        if (!equal(out[file],after?p->after_hash[file]:p->before_hash[file],32)) return -84;
    }
    return 0;
}
static lp_i64 close_pair(const struct lp_io *io, struct lp_workspace *w) {
    lp_i64 first=0;
    for (u32 i=0; i<2; i++) if (w->fd[i]>=0) {
        lp_i64 fd=w->fd[i]; w->fd[i]=-1;
        lp_i64 rc=io->close(io->context,fd);
        if (rc && !first) first=rc;
    }
    return first;
}
static lp_i64 open_pair(const struct lp_plan *p, const struct lp_io *io,
                        struct lp_workspace *w, int writable) {
    for (u32 i=0; i<2; i++) {
        w->fd[i]=io->open(io->context,i,(u32)writable);
        if (w->fd[i]<0) return w->fd[i];
        struct lp_stat st;
        lp_i64 rc=io->stat(io->context,w->fd[i],&st);
        if (rc) return rc;
        if ((st.mode&0170000)!=0100000 || st.size!=p->size[i] || st.links!=1) return -22;
        if (writable) {
            const struct lp_stat *old=&w->original[i];
            if (st.device!=old->device || st.inode!=old->inode || st.mode!=old->mode ||
                st.uid!=old->uid || st.gid!=old->gid) return -116;
        } else w->original[i]=st;
    }
    return 0;
}
static lp_i64 validate(const struct lp_plan *p, const struct lp_io *io) {
    if (!p || !io || !io->begin || !io->end || !io->writable || !io->open ||
        !io->close || !io->stat || !io->read || !io->write || !io->sync) return -22;
    if (!p->windows || !p->count || p->count>4096 || !p->size[0] || !p->size[1] ||
        p->size[0]>0x7fffffffffffffffULL || p->size[1]>0x7fffffffffffffffULL) return -22;
    for (u32 i=0; i<p->count; i++) {
        const struct lp_window *x=p->windows+i;
        if (x->file>1 || !x->length || x->length>4096 || !x->before || !x->after ||
            x->offset>p->size[x->file] || x->length>p->size[x->file]-x->offset) return -22;
        /* Window order encodes payload-before-entry dependencies. Validate
         * non-overlap independently instead of forcing ascending offsets. */
        for (u32 j=0; j<i; j++) {
            const struct lp_window *prev=p->windows+j;
            if (prev->file==x->file && prev->offset<x->offset+x->length &&
                x->offset<prev->offset+prev->length) return -22;
        }
    }
    return 0;
}
static lp_i64 windows(const struct lp_plan *p, const struct lp_io *io,
                      struct lp_workspace *w, struct lp_report *r, int after) {
    for (u32 step=0; step<p->count; step++) {
        const struct lp_window *x=p->windows+(after?step:p->count-1-step);
        r->writes_started=1;  /* before the first syscall; even an error is uncertain */
        lp_i64 rc=transfer(io,w->fd[x->file],(void *)(after?x->after:x->before),x->length,x->offset,1);
        if (rc) return rc;
    }
    for (u32 file=0; file<2; file++) {
        lp_i64 rc=io->sync(io->context,w->fd[file]); if (rc) return rc;
    }
    return 0;
}
void lp_run(const struct lp_plan *p, const struct lp_io *io,
            struct lp_workspace *w, struct lp_report *r) {
    if (!r) return;
    clear(r,sizeof(*r)); r->version=1;
    if (!w) { r->status=-22; r->outcome=LP_REJECTED; return; }
    w->fd[0]=w->fd[1]=-1;
    r->status=validate(p,io);
    if (r->status) { r->outcome=LP_REJECTED; return; }
    for (u32 i=0; i<32; i++) r->operation_id[i]=p->operation_id[i];
    r->phase=LP_BEGIN;
    r->status=io->begin(io->context);
    if (r->status) { r->outcome=LP_REJECTED; return; }
    int writable_attempted=0;
    r->phase=LP_SOURCE;
    r->status=io->writable(io->context,0); if (r->status) goto cleanup;
    r->status=open_pair(p,io,w,0); if (r->status) goto cleanup;
    r->status=verify(p,io,w,0,r->before_hash); if (r->status) goto cleanup;
    /* Also establish that embedded preimage bytes agree with the source.
     * A bad generated rollback table must fail before changing the mount. */
    for (u32 i=0; i<p->count; i++) {
        const struct lp_window *x=p->windows+i;
        r->status=transfer(io,w->fd[x->file],w->buffer,x->length,x->offset,0);
        if (r->status) goto cleanup;
        if (!equal(w->buffer,x->before,x->length)) { r->status=-84; goto cleanup; }
    }
    r->source_verified=1;
    r->status=close_pair(io,w); if (r->status) goto cleanup;
    r->phase=LP_REOPEN;
    writable_attempted=1;
    r->status=io->writable(io->context,1); if (r->status) goto cleanup;
    r->status=open_pair(p,io,w,1); if (r->status) goto cleanup;
    r->status=verify(p,io,w,0,r->before_hash); if (r->status) goto cleanup;
    r->phase=LP_WRITE;
    r->status=windows(p,io,w,r,1);
    if (!r->status) {
        r->phase=LP_TARGET;
        r->status=verify(p,io,w,1,r->after_hash);
    }
    if (r->status && r->writes_started) {
        r->phase=LP_ROLLBACK;
        r->rollback_status=windows(p,io,w,r,0);
        if (!r->rollback_status) r->rollback_status=verify(p,io,w,0,r->after_hash);
        r->rollback_verified=r->rollback_status==0;
    }
cleanup:
    /* Retain the failure phase; cleanup errors are independent evidence. */
    r->cleanup_status=close_pair(io,w);
    if (writable_attempted) {
        lp_i64 rc=io->writable(io->context,0);
        if (rc && !r->cleanup_status) r->cleanup_status=rc;
    }
    lp_i64 rc=io->end(io->context);
    if (rc && !r->cleanup_status) r->cleanup_status=rc;
    if (r->cleanup_status) r->outcome=LP_UNKNOWN;
    else if (!r->status) { r->outcome=LP_WRITTEN; r->phase=LP_DONE; }
    else if (r->rollback_verified) r->outcome=LP_ROLLED_BACK;
    else r->outcome=r->writes_started ? LP_UNKNOWN : LP_REJECTED;
}
