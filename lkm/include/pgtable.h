/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * LKM shim for the KernelPatch page-table helpers.
 *
 * The in-tree build compiles against kernel/include/pgtable.h directly. The LKM
 * has two include roots - lkm/include first, then kernel/include - and this file
 * used to be a six-line stub that only pulled asm/barrier.h. That was enough
 * while nothing under lkm/ touched page tables, but selinux_hook patches the
 * selinuxfs write_op pointer table through a manual PTE walk, so it needs the
 * real pgtable_entry(), flush_tlb_kernel_page() and the PTE_* bit definitions.
 *
 * Rather than keep two copies in sync, forward to the authoritative header. The
 * kernel side is pure declarations and static inlines over ktypes.h, so it
 * compiles unchanged in module context.
 */
#ifndef _KP_LKM_PGTABLE_H_
#define _KP_LKM_PGTABLE_H_

#include <asm/barrier.h>

/* lkm/include and kernel/include are both on the include path, so a plain
 * #include <pgtable.h> would recurse into this file. Reach the real one by its
 * path relative to the module root instead. */
#include "../../kernel/include/pgtable.h"

#endif /* _KP_LKM_PGTABLE_H_ */
