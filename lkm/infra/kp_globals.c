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
 * references and the loader failed with "No such file or directory" - which is
 * exactly what the module loader reports for an unresolved symbol (ENOENT).
 *
 * Every definition here is standalone: no kfunc() dispatch table, no
 * image-side address layout, just the kernel's own APIs and headers.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/stddef.h>

/* ---- kver -------------------------------------------------------------
 *
 * KernelPatch's own build number, distinct from LINUX_VERSION_CODE: it records
 * the kernel the code was compiled against so the runtime comparisons against
 * VERSION(a, b, c) keep that meaning. start.c initializes the image copy to 0
 * and lets the entry code fill it in; here the compiler already knows.
 */
uint32_t kver = LINUX_VERSION_CODE;

/* ---- compat_copy_to_user ----------------------------------------------
 *
 * The image-side version probes seq_buf_to_user / bits_to_user / xt_data_to_user
 * at runtime, because those are the only copy_to_user-shaped entry points a
 * packed image can reach without the module machinery.
 *
 * A module links the ordinary accessors, so copy_to_user() is enough. Return
 * convention is unchanged: number of bytes NOT copied, zero on success.
 */
int __must_check compat_copy_to_user(void __user *to, const void *from, int n)
{
    if (!to || !from || n <= 0)
        return n;

    return (int)copy_to_user(to, from, (unsigned long)n);
}

/* ---- compat_strncpy_from_user ----------------------------------------
 *
 * Same reasoning; strncpy_from_user() is linked normally. Returns the copied
 * length, or -EFAULT, matching strncpy_from_user().
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
 * KernelPatch resolves all of these by scanning task_struct at boot, because
 * the image has no KMI and must work on any vendor kernel. A module is built
 * against the kernel's own headers, so offsetof() gives the answer at compile
 * time and the field is a table of constants.
 *
 * -1 still means "not available", so callers testing <= 0 take the slow path.
 * Only tasks_offset and comm_offset are consumed today (selinux_hook walks the
 * task list looking for magiskinit); the rest are filled in for completeness.
 */
struct task_struct_offset {
    int pid_offset;
    int tgid_offset;
    int real_cred_offset;
    int cred_offset;
    int fs_offset;
    int files_offset;
    int comm_offset;
    int stack_offset;
    int tasks_offset;
    int mm_offset;
    int active_mm_offset;
};

struct task_struct_offset task_struct_offset = {
    .pid_offset       = (int)offsetof(struct task_struct, pid),
    .tgid_offset      = (int)offsetof(struct task_struct, tgid),
    .real_cred_offset = (int)offsetof(struct task_struct, real_cred),
    .cred_offset      = (int)offsetof(struct task_struct, cred),
    .fs_offset        = (int)offsetof(struct task_struct, fs),
    .files_offset     = (int)offsetof(struct task_struct, files),
    .comm_offset      = (int)offsetof(struct task_struct, comm),
    .stack_offset     = (int)offsetof(struct task_struct, stack),
    .tasks_offset     = (int)offsetof(struct task_struct, tasks),
    .mm_offset        = (int)offsetof(struct task_struct, mm),
    .active_mm_offset = (int)offsetof(struct task_struct, active_mm),
};

/* ---- pgtable_entry ----------------------------------------------------
 *
 * Ported from kernel/base/start.c. That version reads page_shift / page_level
 * from the image's boot-time globals; a module takes both from the headers, so
 * they are compile-time constants here.
 *
 * Walks from @pgd to the leaf entry covering @va and returns a pointer into the
 * live page table, or NULL when a level is missing. Flag-bit layout is
 * architecture-wide, so no cache maintenance is needed in the walk itself:
 * callers that mutate the returned entry do their own TLBI.
 */
uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
#if defined(CONFIG_ARM64) && defined(CONFIG_ARM64_4K_PAGES)
    const uint64_t pshift = PAGE_SHIFT;                 /* 12 */
    const uint64_t pxd_bits = pshift - 3;               /* 9 */
    const uint64_t pxd_ptrs = 1UL << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_entry_va = 0;
    int lv;

    /* 4K pages: four levels, start at level 0 (PGD). */
    for (lv = 0; lv < 4; lv++) {
        uint64_t pxd_shift = pxd_bits * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        uint64_t pxd_desc;
        uint64_t pxd_pa;

        pxd_entry_va = pxd_va + pxd_index * 8;
        pxd_desc = *(uint64_t *)pxd_entry_va;

        if ((pxd_desc & 0x3) == 0x3) {
            /* table descriptor: follow to the next level */
            pxd_pa = pxd_desc & (((1UL << (48 - pshift)) - 1) << pshift);
        } else if ((pxd_desc & 0x3) == 0x1) {
            /* block descriptor: this entry is the leaf */
            return (uint64_t *)pxd_entry_va;
        } else {
            return NULL;
        }

        pxd_va = (uint64_t)__va(pxd_pa);
    }
    return (uint64_t *)pxd_entry_va;
#else
    /* 16K/64K page kernels and x86: not needed by any caller in this tree, and
     * the level layout differs. Return NULL so callers fall back. */
    (void)pgd;
    (void)va;
    return NULL;
#endif
}
