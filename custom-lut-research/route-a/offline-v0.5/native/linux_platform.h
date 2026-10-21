#ifndef LP_LINUX_PLATFORM_H
#define LP_LINUX_PLATFORM_H
#include "pair_core.h"
/* Kernel calls use Linux AArch64 numbers and raw negative errno results.
 * quiesce_enter MUST establish application/firmware-reader exclusion and undo
 * partial acquisition on failure. A file lock alone does not satisfy it.
 * There is deliberately no built-in successful camera quiescence callback. */
typedef lp_i64 (*lp_syscall)(void *,lp_i64,lp_i64,lp_i64,lp_i64,lp_i64,lp_i64,lp_i64);
struct lp_linux_services {
    void *context;
    lp_syscall syscall;
    lp_i64 (*quiesce_enter)(void *);
    lp_i64 (*quiesce_leave)(void *);
};
struct lp_linux {
    struct lp_linux_services services;
    struct lp_io io;
    lp_i64 dirs[5], lock_fd, files[2]; /* usr,lib,cp,tmp,jiritsu */
    lp_u64 device[2];
    lp_u32 active, quiesced, writing, remount_attempted;
    lp_u64 mount_flags;
    char usr_options[256], cp_options[512];
    lp_u8 mounts[32768];
};
void lp_linux_init(struct lp_linux *,const struct lp_linux_services *);
/* No syscall function on non-AArch64 builds. The fixture supplies one. */
#if defined(__aarch64__) && !defined(LP_HOST_TEST)
lp_i64 lp_linux_syscall(void *,lp_i64,lp_i64,lp_i64,lp_i64,lp_i64,lp_i64,lp_i64);
#endif
#endif
