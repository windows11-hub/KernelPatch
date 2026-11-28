/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * LKM shim for the KernelPatch page-table helper.
 *
 * selinux_hook patches the selinuxfs write_op pointer table with a manual PTE
 * walk, so it needs pgtable_entry(). It gets the PTE bits and the TLBI sequence
 * from its own definitions (SELINUX_PTE_* / selinux_flush_tlb_kernel_page), so
 * pgtable_entry() is the only symbol it takes from here.
 *
 * Do NOT include ../../kernel/include/pgtable.h: that header pulls ktypes.h,
 * which defines KernelPatch's userland compiler attributes (__pure, __aligned,
 * __printf, notrace, ...). Those collide head-on with linux/compiler.h and the
 * kernel build rejects every one of them as a macro redefinition. Declaring the
 * single function we need keeps the two worlds apart.
 */
#ifndef _KP_LKM_PGTABLE_H_
#define _KP_LKM_PGTABLE_H_

#include <asm/barrier.h>

/* Walk four levels from @pgd to the leaf PTE covering @va and return a pointer
 * to that entry, or NULL when any level is missing. Implemented in the module
 * against swapper_pg_dir / init_pg_dir. */
uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);

#endif /* _KP_LKM_PGTABLE_H_ */
