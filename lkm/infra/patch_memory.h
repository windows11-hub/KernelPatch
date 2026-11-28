/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * arm64 kernel memory patching and executable-mapping control.
 *
 * The short version of why this exists instead of a call to set_memory_x:
 * on the OPPO 6.6 kernel neither set_memory_x, module_alloc, module_memfree,
 * __vmalloc_node_range nor init_mm is exported to modules. vmalloc, vfree,
 * is_vmalloc_addr and kallsyms_lookup_name are. So executable memory is made
 * by allocating with vmalloc and rewriting the swapper page tables directly.
 */
#ifndef _KP_LKM_PATCH_MEMORY_H_
#define _KP_LKM_PATCH_MEMORY_H_
#include <linux/types.h>

/* Only arm64 is wired up in the framework. */
#ifndef __aarch64__
#error "kp lkm framework: only arm64 is wired up for now"
#endif

#define KP_PATCH_TEXT_FLUSH_DCACHE 1
#define KP_PATCH_TEXT_FLUSH_ICACHE 2

/* Resolve the swapper page tables. */
int kp_patch_memory_init(void);

/* Write @len bytes at @src into kernel memory at @dst, going through a fixmap
 * alias so read-only pages can be written. */
int kp_patch_text(void *dst, const void *src, size_t len, int flags);

/* Allocate @size bytes of RWX kernel memory (vmalloc + page-table rewrite).
 * Returns NULL if the swapper tables are unavailable or the mapping could not
 * be made executable - in that case no hook must be installed, because a BR
 * into a non-executable page faults immediately. */
void *kp_alloc_exec(unsigned long size);
void kp_free_exec(void *p);

#endif /* _KP_LKM_PATCH_MEMORY_H_ */
