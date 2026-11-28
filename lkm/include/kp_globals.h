/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Shared definitions for the KernelPatch globals that a loadable module has to
 * carry itself: kver, the task_struct offset table, the compat user-copy
 * helpers and the page-table walker.
 *
 * The in-tree build gets these from the packed kernel image (kernel/base/start.c
 * and kernel/patch/common/utils.c) plus the KPM loader's symbol table. A module
 * has neither, so infra/kp_globals.c defines them and this header is the single
 * place that declares them. Files that only need to link against them include
 * this instead of re-declaring, which used to let the types drift apart.
 */
#ifndef _KP_LKM_KP_GLOBALS_H_
#define _KP_LKM_KP_GLOBALS_H_

#include <linux/types.h>
#include <linux/version.h>

/* KernelPatch build number, from the headers this module was compiled against. */
extern uint32_t kver;

#define VERSION(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))

/* User-copy helpers with the return conventions the KernelPatch image uses:
 * compat_copy_to_user returns bytes NOT copied, compat_strncpy_from_user
 * returns the copied length or -EFAULT. */
extern int __must_check compat_copy_to_user(void __user *to, const void *from, int n);
extern long compat_strncpy_from_user(char *dest, const char __user *src, long count);

/* Resolved task_struct field offsets. -1 means "not available"; callers must
 * treat <= 0 as "skip this field" rather than reading offset -1. */
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
extern struct task_struct_offset task_struct_offset;

/* Walk from @pgd to the leaf PTE covering @va. NULL when a level is missing or
 * the page size is not 4K. */
extern uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);

#endif /* _KP_LKM_KP_GLOBALS_H_ */
