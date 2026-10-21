#include "linux_platform.h"
/* Fixed ILCE-7CM2 2.01 filesystem profile from the saved native probe:
 * /usr: /dev/nflasha15 ext2 initially ro; /cp: /dev/nflasha8 vfat rw.
 * Only /usr is remounted. /cp's original writable mount is preserved;
 * descriptor permissions and writing state restrict this worker's writes. */
enum { NR_FLOCK=32, NR_MOUNT=40, NR_OPENAT=56, NR_CLOSE=57, NR_READ=63,
       NR_PREAD=67, NR_PWRITE=68, NR_FSTAT=80, NR_FSYNC=82, NR_GETEUID=175 };
enum { RDONLY=0, RDWR=2, CREAT=64, DIRECTORY=16384, NOFOLLOW=32768, CLOEXEC=524288 };
struct kernel_stat {
    lp_u64 dev,ino; lp_u32 mode,nlink,uid,gid; lp_u64 rdev,pad1;
    lp_i64 size; lp_u32 blksize,pad2; lp_u64 blocks,rest[7];
};
_Static_assert(sizeof(struct kernel_stat)==128,"Linux AArch64 stat ABI");
_Static_assert(__builtin_offsetof(struct kernel_stat,size)==48,"stat size offset");
_Static_assert(__builtin_offsetof(struct kernel_stat,mode)==16,"stat mode offset");
static lp_i64 sys(struct lp_linux *s,lp_i64 n,lp_i64 a,lp_i64 b,lp_i64 c,lp_i64 d,lp_i64 e) {
    return s->services.syscall(s->services.context,n,a,b,c,d,e,0);
}
static lp_i64 close_one(struct lp_linux *s,lp_i64 *fd) {
    if (*fd<0) return 0;
    lp_i64 f=*fd; *fd=-1; return sys(s,NR_CLOSE,f,0,0,0,0);
}
static lp_i64 fstat(struct lp_linux *s,lp_i64 fd,struct kernel_stat *st) {
    return sys(s,NR_FSTAT,fd,(lp_i64)st,0,0,0);
}
static int equal(const char *a,const lp_u8 *b,lp_u32 n) {
    lp_u32 i=0; for(;i<n;i++) if(!a[i] || (lp_u8)a[i]!=b[i]) return 0;
    return a[i]==0;
}
static int token(const lp_u8 *p,lp_u32 n,const char *v) {return equal(v,p,n);}
static lp_i64 open_dir(struct lp_linux *s,lp_i64 parent,const char *path,lp_i64 *out,lp_u64 *device) {
    *out=sys(s,NR_OPENAT,parent,(lp_i64)path,DIRECTORY|NOFOLLOW|CLOEXEC,0,0);
    if(*out<0)return *out;
    struct kernel_stat st; lp_i64 rc=fstat(s,*out,&st);
    if(rc)return rc;
    if((st.mode&0170000)!=0040000 || st.uid!=0 || (st.mode&0022))return -13;
    if(device)*device=st.dev;
    return 0;
}
/* Normalize the single ro/rw token to 'r?' so state comparisons preserve every
 * other option byte. No prefix matching, duplicate modes or truncated rows. */
static lp_i64 options(const lp_u8 *p,lp_u32 n,char *out,lp_u32 capacity,int wanted,lp_u64 *flags) {
    if(n>=capacity)return -75;
    lp_u32 begin=0,modes=0; lp_u64 bits=0;
    for(lp_u32 i=0;i<=n;i++) if(i==n || p[i]==',') {
        lp_u32 len=i-begin; const lp_u8 *q=p+begin;
        if(!len)return -22;
        if(token(q,len,"ro") || token(q,len,"rw")) {
            if(++modes!=1 || q[1]!=(wanted?'o':'w'))return -30;
        } else if(flags) {
            if(token(q,len,"sync"))bits|=16;
            else if(token(q,len,"dirsync"))bits|=128;
            else if(token(q,len,"nosuid"))bits|=2;
            else if(token(q,len,"nodev"))bits|=4;
            else if(token(q,len,"noexec"))bits|=8;
            else if(token(q,len,"noatime"))bits|=1024;
            else if(token(q,len,"nodiratime"))bits|=2048;
            else if(token(q,len,"relatime"))bits|=2097152;
            else if(token(q,len,"strictatime"))bits|=16777216;
            else if(token(q,len,"errors=continue") || token(q,len,"errors=remount-ro") || token(q,len,"errors=panic")) {}
            else return -95; /* do not silently discard unknown mount policy */
        }
        for(lp_u32 j=begin;j<i;j++)out[j]=(char)p[j];
        if(len==2 && q[0]=='r' && (q[1]=='o'||q[1]=='w'))out[begin+1]='?';
        if(i<n)out[i]=',';
        begin=i+1;
    }
    if(modes!=1)return -22;
    out[n]=0;if(flags)*flags=bits;return 0;
}
static int strings_equal(const char *a,const char *b) {
    for(lp_u32 i=0;;i++){if(a[i]!=b[i])return 0;if(!a[i])return 1;}
}
static lp_i64 mounts(struct lp_linux *s,int ro,int capture) {
    lp_i64 fd=sys(s,NR_OPENAT,-100,(lp_i64)"/proc/mounts",CLOEXEC,0,0);
    if(fd<0)return fd;
    lp_u32 used=0,retries=0;lp_i64 rc=0;
    while(used<sizeof(s->mounts)) {
        lp_i64 n=sys(s,NR_READ,fd,(lp_i64)(s->mounts+used),sizeof(s->mounts)-used,0,0);
        if(n==-4 && retries++<3)continue;
        if(n<0){rc=n;break;} if(!n)break;
        if((lp_u64)n>sizeof(s->mounts)-used){rc=-5;break;}
        used+=(lp_u32)n;
    }
    lp_i64 closed=close_one(s,&fd);if(rc)return rc;if(closed)return closed;
    if(!used || used==sizeof(s->mounts) || s->mounts[used-1]!='\n')return -75;
    lp_u32 start=0,seen[2]={0,0};
    for(lp_u32 end=0;end<used;end++)if(s->mounts[end]=='\n') {
        lp_u32 fields[6],length[6],count=0,at=start;
        while(at<end && count<6) {
            fields[count]=at;
            while(at<end && s->mounts[at]!=' ')at++;
            length[count]=at-fields[count];count++;
            if(at<end)at++;
        }
        if(count!=6 || at!=end)return -22;
        int file=token(s->mounts+fields[1],length[1],"/usr")?0:token(s->mounts+fields[1],length[1],"/cp")?1:-1;
        if(file>=0) {
            if(++seen[file]!=1)return -22;
            if(!token(s->mounts+fields[0],length[0],file?"/dev/nflasha8":"/dev/nflasha15") ||
               !token(s->mounts+fields[2],length[2],file?"vfat":"ext2"))return -18;
            char out[512];lp_u64 bits=0;
            rc=options(s->mounts+fields[3],length[3],out,file?512:256,file?0:ro,file?0:&bits);
            if(rc)return rc;
            char *saved=file?s->cp_options:s->usr_options;
            if(capture){lp_u32 i=0;do{saved[i]=out[i];}while(out[i++]);if(!file)s->mount_flags=bits;}
            else if(!strings_equal(saved,out) || (!file && bits!=s->mount_flags))return -116;
        }
        start=end+1;
    }
    return seen[0]==1 && seen[1]==1?0:-22;
}
static lp_i64 end(void *ctx) {
    struct lp_linux *s=ctx;lp_i64 first=0,rc;
    if(s->files[0]>=0 || s->files[1]>=0)first=-16;
    for(lp_u32 i=0;i<2;i++){rc=close_one(s,&s->files[i]);if(rc&&!first)first=rc;}
    /* Keep application exclusion until all descriptor cleanup has run. */
    for(lp_u32 i=5;i>0;i--){rc=close_one(s,&s->dirs[i-1]);if(rc&&!first)first=rc;}
    if(s->quiesced){s->quiesced=0;rc=s->services.quiesce_leave(s->services.context);if(rc&&!first)first=rc;}
    if(s->lock_fd>=0){rc=sys(s,NR_FLOCK,s->lock_fd,8,0,0,0);if(rc&&!first)first=rc;rc=close_one(s,&s->lock_fd);if(rc&&!first)first=rc;}
    s->active=s->writing=0;return first;
}
static lp_i64 begin(void *ctx) {
    struct lp_linux *s=ctx;
    if(!s->services.syscall || !s->services.quiesce_enter || !s->services.quiesce_leave)return -95;
    if(s->active)return -16;
    if(sys(s,NR_GETEUID,0,0,0,0,0)!=0)return -13;
    lp_i64 root=-1,rc;lp_u64 lib_device=0;
    rc=open_dir(s,-100,"/",&root,0);if(rc)goto fail;
    rc=open_dir(s,root,"tmp",&s->dirs[3],0);if(rc)goto fail;
    rc=open_dir(s,s->dirs[3],"jiritsu",&s->dirs[4],0);if(rc)goto fail;
    s->lock_fd=sys(s,NR_OPENAT,s->dirs[4],(lp_i64)"a7c2.lut.pair.lock",RDWR|CREAT|NOFOLLOW|CLOEXEC,0600,0);
    if(s->lock_fd<0){rc=s->lock_fd;goto fail;}
    struct kernel_stat st;rc=fstat(s,s->lock_fd,&st);if(rc)goto fail;
    if((st.mode&0170000)!=0100000 || st.uid!=0 || st.nlink!=1 || (st.mode&0022)){rc=-13;goto fail;}
    rc=sys(s,NR_FLOCK,s->lock_fd,2|4,0,0,0);if(rc)goto fail;
    rc=s->services.quiesce_enter(s->services.context);if(rc)goto fail;
    s->quiesced=1;
    rc=mounts(s,1,1);if(rc)goto fail;
    rc=open_dir(s,root,"usr",&s->dirs[0],&s->device[0]);if(rc)goto fail;
    rc=open_dir(s,s->dirs[0],"lib",&s->dirs[1],&lib_device);if(rc)goto fail;
    if(lib_device!=s->device[0]){rc=-18;goto fail;}
    rc=open_dir(s,root,"cp",&s->dirs[2],&s->device[1]);if(rc)goto fail;
    rc=close_one(s,&root);if(rc)goto fail;
    s->active=1;s->writing=s->remount_attempted=0;return 0;
fail:
    {lp_i64 close_rc=close_one(s,&root),clean=end(s);return clean?clean:close_rc?close_rc:rc;}
}
static lp_i64 writable(void *ctx,lp_u32 enable) {
    struct lp_linux *s=ctx;if(!s->active || enable>1)return -22;
    if(s->files[0]>=0 || s->files[1]>=0)return -16;
    if(enable || s->remount_attempted) {
        if(enable){lp_i64 rc=mounts(s,1,0);if(rc)return rc;}
        s->writing=0;s->remount_attempted=1;
        lp_i64 rc=sys(s,NR_MOUNT,0,(lp_i64)"/usr",0,(lp_i64)(s->mount_flags|32|(enable?0:1)),0);
        if(rc)return rc;
        rc=mounts(s,!enable,0);if(rc)return rc;
        s->writing=enable;if(!enable)s->remount_attempted=0;return 0;
    }
    return mounts(s,1,0);
}
static lp_i64 open_file(void *ctx,lp_u32 file,lp_u32 writing) {
    struct lp_linux *s=ctx;
    if(!s->active || file>1 || writing>1 || writing!=s->writing || s->files[file]>=0)return -22;
    lp_i64 fd=sys(s,NR_OPENAT,s->dirs[file?2:1],(lp_i64)(file?"cpapp-b.bin":"appFw.so"),
                 (writing?RDWR:RDONLY)|NOFOLLOW|CLOEXEC,0,0);
    if(fd>=0)s->files[file]=fd;return fd;
}
static int file_index(struct lp_linux *s,lp_i64 fd) {
    if(!s->active || fd<0)return -1;
    for(int i=0;i<2;i++)if(s->files[i]==fd)return i;return -1;
}
static lp_i64 close_file(void *ctx,lp_i64 fd) {
    struct lp_linux *s=ctx;int i=file_index(s,fd);if(i<0)return -9;return close_one(s,&s->files[i]);
}
static lp_i64 stat_file(void *ctx,lp_i64 fd,struct lp_stat *out) {
    struct lp_linux *s=ctx;int i=file_index(s,fd);if(i<0 || !out)return -9;
    struct kernel_stat st;lp_i64 rc=fstat(s,fd,&st);if(rc)return rc;
    if(st.size<0 || st.dev!=s->device[i])return -18;
    out->device=st.dev;out->inode=st.ino;out->size=(lp_u64)st.size;out->mode=st.mode;
    out->uid=st.uid;out->gid=st.gid;out->links=st.nlink;return 0;
}
static lp_i64 read_file(void *ctx,lp_i64 fd,void *out,lp_u32 n,lp_u64 at) {
    struct lp_linux *s=ctx;if(file_index(s,fd)<0)return -9;
    return sys(s,NR_PREAD,fd,(lp_i64)out,n,(lp_i64)at,0);
}
static lp_i64 write_file(void *ctx,lp_i64 fd,const void *data,lp_u32 n,lp_u64 at) {
    struct lp_linux *s=ctx;if(file_index(s,fd)<0 || !s->writing)return -9;
    return sys(s,NR_PWRITE,fd,(lp_i64)data,n,(lp_i64)at,0);
}
static lp_i64 sync_file(void *ctx,lp_i64 fd) {
    struct lp_linux *s=ctx;if(file_index(s,fd)<0)return -9;return sys(s,NR_FSYNC,fd,0,0,0,0);
}
void lp_linux_init(struct lp_linux *s,const struct lp_linux_services *services) {
    lp_u8 *p=(lp_u8 *)s;for(lp_u32 i=0;i<sizeof(*s);i++)p[i]=0;
    s->services=*services;
    for(lp_u32 i=0;i<5;i++)s->dirs[i]=-1;
    for(lp_u32 i=0;i<2;i++)s->files[i]=-1;
    s->lock_fd=-1;
    struct lp_io *io=&s->io;io->context=s;io->begin=begin;io->end=end;io->writable=writable;
    io->open=open_file;io->close=close_file;io->stat=stat_file;io->read=read_file;io->write=write_file;io->sync=sync_file;
}
#if defined(__aarch64__) && !defined(LP_HOST_TEST)
lp_i64 lp_linux_syscall(void *ctx,lp_i64 n,lp_i64 a,lp_i64 b,lp_i64 c,lp_i64 d,lp_i64 e,lp_i64 f) {
    (void)ctx;
    register lp_i64 x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register lp_i64 x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8) : "memory","cc");
    return x0;
}
#endif
