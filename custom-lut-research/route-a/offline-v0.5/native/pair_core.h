#ifndef LUT_PAIR_CORE_H
#define LUT_PAIR_CORE_H
/* Portable transaction engine. No paths, discovery, settings or raw flash.
 * The platform supplies a fixed-file, exclusive session and syscall results.
 * All callbacks return nonnegative success or a negative error; I/O returns
 * byte counts. Only read/write EINTR (-4) is retried, with a finite limit. */
typedef unsigned long long lp_u64;
typedef unsigned int lp_u32;
typedef long long lp_i64;
typedef unsigned char lp_u8;
struct lp_stat {
    lp_u64 device, inode, size;
    lp_u32 mode, uid, gid, links;
};
struct lp_window {
    lp_u64 offset;
    lp_u32 file, length;
    const lp_u8 *before, *after;
};
struct lp_plan {
    lp_u64 size[2];
    lp_u8 before_hash[2][32], after_hash[2][32], operation_id[32];
    const struct lp_window *windows;
    lp_u32 count;
};
struct lp_io {
    void *context;
    lp_i64 (*begin)(void *);
    lp_i64 (*end)(void *);
    lp_i64 (*writable)(void *, lp_u32);
    lp_i64 (*open)(void *, lp_u32, lp_u32);
    lp_i64 (*close)(void *, lp_i64);
    lp_i64 (*stat)(void *, lp_i64, struct lp_stat *);
    lp_i64 (*read)(void *, lp_i64, void *, lp_u32, lp_u64);
    lp_i64 (*write)(void *, lp_i64, const void *, lp_u32, lp_u64);
    lp_i64 (*sync)(void *, lp_i64);
};
enum lp_outcome { LP_UNKNOWN=0, LP_WRITTEN=1, LP_ROLLED_BACK=2, LP_REJECTED=3 };
enum lp_phase { LP_VALIDATE=0, LP_BEGIN=1, LP_SOURCE=2, LP_REOPEN=3,
                LP_WRITE=4, LP_TARGET=5, LP_ROLLBACK=6, LP_CLEANUP=7, LP_DONE=8 };
struct lp_report {
    lp_u32 version, outcome, phase, source_verified, writes_started, rollback_verified;
    lp_i64 status, rollback_status, cleanup_status;
    lp_u8 operation_id[32], before_hash[2][32], after_hash[2][32];
};
struct lp_workspace {
    lp_u8 buffer[4096];
    struct lp_stat original[2];
    lp_i64 fd[2];
};
void lp_run(const struct lp_plan *, const struct lp_io *, struct lp_workspace *, struct lp_report *);
#endif
