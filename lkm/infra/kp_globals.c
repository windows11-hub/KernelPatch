// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KernelPatch globals and helpers that the LKM used to inherit from the packed
 * kernel image.
 *
 * In the in-tree build these live in kernel/base/start.c (a bare-metal entry
 * image) and kernel/patch/common/utils.c, and a KPM links against them through
 * the KPM loader's symbol table. A loadable module has no such table: anything
 * it references must either be EXPORT_SYMBOL'd by the kernel or defined inside
 * the module itself. These were neither, so the .ko carried them as undefined
 * references and the loader failed with "no such file or directory" (ENOENT is
 * exactly what the module loader reports for an unresolved symbol).
 *
 * Definitions here are deliberately minimal and standalone: no kfunc() table,
 * no image-side address layout, just the kernel's own APIs.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

#include "../infra/symbol_resolver.h"

/* ---- kver -------------------------------------------------------------
 *
 * KernelPatch's own build number, distinct from LINUX_VERSION_CODE: it is
 * produced from the header the module was compiled against, so the runtime
 * checks that compare against VERSION(a, b, c) keep meaning "the kernel I was
 * built for". start.c initializes the image copy to 0 and lets the entry code
 * fill it in; here the compiler already knows the answer.
 */
uint32_t kver = LINUX_VERSION_CODE;

/* ---- compat_copy_to_user ----------------------------------------------
 *
 * The image-side version routes through whichever of seq_buf_to_user /
 * bits_to_user / xt_data_to_user it can resolve at runtime, because those are
 * the only copy_to_user-shaped entry points that are reliably reachable from a
 * packed image with no module machinery.
 *
 * In a module the ordinary accessors are available, so copy_to_user() is
 * enough; the return value follows the same convention (number of bytes NOT
 * copied), because selinux_hook only checks it for zero.
 */
int __must_check compat_copy_to_user(void __user *to, const void *from, int n)
{
    if (!to || !from || n <= 0)
        return n;

    return (int)copy_to_user(to, from, (unsigned long)n);
}

/* ---- compat_strncpy_from_user ----------------------------------------
 *
 * Same story: strncpy_from_user() is linked normally here. The image version
 * has to probe strncpy_from_user / strncpy_from_user_nofault by hand. Return
 * convention matches strncpy_from_user: length copied, or -EFAULT.
 */
long compat_strncpy_from_user(char *dest, const char __user *src, long count)
{
    long rc;

    if (!dest || !src || count <= 0)
        return 0;

    rc = strncpy_from_user(dest, src, count);
    if (rc < 0)
        return rc;
    if (rc >= count) {
        rc = count - 1;
        dest[rc] = '\0';
    }
    return rc;
}

/* ---- task_struct_offset -----------------------------------------------
 *
 * KernelPatch resolves every one of these by scanning task_struct at boot,
 * because the image has no KMI and has to work across vendor kernels. A module
 * is built against the kernel's own headers, so the offsets are compile-time
 * constants and the field is filled from offsetof() instead.
 *
 * -1 keeps meaning "not resolved", so callers that test <= 0 still behave.
 */
struct kp_task_struct_offset_local {
    int pid_offset;
    int tgid_offset;
    int thread_pid_offset;
    int ptracer_cred_offset;
    int real_cred_offset;
    int cred_offset;
    int fs_offset;
    int files_offset;
    int loginuid_offset;
    int sessionid_offset;
    int comm_offset;
    int seccomp_offset;
    int security_offset;
    int stack_offset;
    int tasks_offset;
    int mm_offset;
    int active_mm_offset;
} task_struct_offset = {
    .pid_offset         = (int)offsetof(struct task_struct, pid),
    .tgid_offset        = (int)offsetof(struct task_struct, tgid),
    .thread_pid_offset  = (int)offsetof(struct task_struct, thread_pid),
    .ptracer_cred_offset = (int)offsetof(struct task_struct, ptracer_cred),
    .real_cred_offset   = (int)offsetof(struct task_struct, real_cred),
    .cred_offset        = (int)offsetof(struct task_struct, cred),
    .fs_offset          = (int)offsetof(struct task_struct, fs),
    .files_offset       = (int)offsetof(struct task_struct, files),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
    .loginuid_offset    = (int)offsetof(struct task_struct, loginuid),
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
    .loginuid_offset    = -1,
#endif
    /* sessionid moved out of task_struct into the audit context long ago; a
     * -1 tells every caller to take the slow path. */
    .sessionid_offset   = -1,
    .comm_offset        = (int)offsetof(struct task_struct, comm),
    .seccomp_offset     = (int)offsetof(struct task_struct, seccomp),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
    .security_offset    = (int)offsetof(struct task_struct, security),
#else
    .security_offset    = -1,
#endif
    .stack_offset       = (int)offsetof(struct task_struct, stack),
    .tasks_offset       = (int)offsetof(struct task_struct, tasks),
    .mm_offset          = (int)offsetof(struct task_struct, mm),
    .active_mm_offset   = (int)offsetof(struct task_struct, active_mm),
};

/* ---- pgtable_entry ----------------------------------------------------
 *
 * Ported from kernel/base/start.c. That version reads page_shift / page_level
 * from the image's boot-time globals; a module gets PAGE_SHIFT and the level
 * count from the headers, so they collapse into compile-time values.
 *
 * Walks from @pgd to the leaf entry covering @va and returns a pointer into the
 * page table, or NULL when any level is missing. The stage-1 flag bits are the
 * same everywhere, so no cache maintenance is needed here: callers that mutate
 * the returned entry do their own TLBI (see selinux_hook).
 */
uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
#if defined(CONFIG_ARM64)
    const uint64_t pshift = PAGE_SHIFT;
    const uint64_t pxd_bits = pshift - 3;
    const uint64_t pxd_ptrs = 1UL << pxd_bits;
    /* ARM64 with 4K pages has 4 levels; 16K/64K start at level 2. */
    const int64_t first_lv = (pshift == 12) ? 0 : 1;
    uint64_t pxd_va = pgd;
    uint64_t pxd_entry_va = 0;

    for (int64_t lv = first_lv; lv < 4; lv++) {
        uint64_t pxd_shift = (pshift - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        uint64_t pxd_desc;
        uint64_t pxd_pa;

        pxd_entry_va = pxd_va + pxd_index * 8;
        pxd_desc = *(uint64_t *)pxd_entry_va;

        if ((pxd_desc & 0x3) == 0x3) {
            /* table descriptor: next level's physical address */
            pxd_pa = pxd_desc & (((1UL << (48 - pshift)) - 1) << pshift);
        } else if ((pxd_desc & 0x3) == 0x1) {
            /* block descriptor: this IS the leaf, stop here */
            return (uint64_t *)pxd_entry_va;
        } else {
            return NULL;
        }

        pxd_va = (uint64_t)__va(pxd_pa);
    }
    return (uint64_t *)pxd_entry_va;
#else
    (void)pgd;
    (void)va;
    return NULL;
#endif
}
