// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * arm64 kernel memory patching and executable-mapping control for the LKM.
 *
 * Why this file does not use the obvious kernel helpers
 * -----------------------------------------------------
 * Everything below was cross-checked against the OPPO 6.6 source
 * (oppo-source/android_kernel_oppo_sm8750, sm8750_b_16.0.0_find_n5). The short
 * version is that none of the "normal" ways to get executable module memory
 * survive as a loadable module on this kernel:
 *
 *   arch/arm64/mm/pageattr.c
 *     exports set_direct_map_invalid_noflush and set_direct_map_default_noflush
 *     only. set_memory_x / set_memory_nx / set_memory_ro are NOT exported, so
 *     a module cannot call them.
 *
 *   kernel/module/main.c
 *     module_alloc and module_memfree are __weak and NOT exported either.
 *
 *   arch/arm64/kernel/module.c
 *     module_alloc allocates with PAGE_KERNEL (PXN set). The pages only become
 *     executable later, in module_enable_x(), which calls set_memory_x through
 *     kernel/module/strict_rwx.c - i.e. from inside the kernel, not from us.
 *
 *   mm/vmalloc.c
 *     __vmalloc_node_range is NOT exported, so PAGE_KERNEL_EXEC cannot be
 *     requested directly. Only vmalloc (PAGE_KERNEL) is available.
 *
 *   mm/init-mm.c
 *     init_mm is not exported, so the mm-based page walk cannot use it.
 *
 * What is exported and does work: vmalloc, vfree, is_vmalloc_addr and
 * kallsyms_lookup_name (the vendor kernel exports the last one - the module
 * would not load otherwise). So:
 *
 *   allocate with vmalloc(), then walk the swapper page tables directly and
 *   clear PXN/GP on the new pages, then flush.
 *
 * swapper_pg_dir is the kernel's top-level table and is reachable by name.
 * Walking it needs no mm_struct at all - pgd_offset_k() works on a bare pgd.
 */
#ifdef __aarch64__

#include "patch_memory.h"
#include "symbol_resolver.h"

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched/task_stack.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/barrier.h>
#include <asm/tlbflush.h>

#include "../include/kp_lkm.h"

/* PTE bits that gate execution and BTI. Values are architectural, not
 * kernel-version dependent. */
#define KP_PTE_PXN	(1UL << 53)
#define KP_PTE_UXN	(1UL << 54)
#define KP_PTE_GP	(1UL << 50)
#define KP_PTE_DBM	(1UL << 51)
#define KP_PTE_RDONLY	(1UL << 7)

/* The kernel's swapper page tables. Resolved by name; not an exported symbol,
 * but kallsyms_lookup_name reaches it. */
static uint64_t *kp_swapper_pg_dir;

/* Cache maintenance, done from inline asm.
 *
 * arch/arm64/mm/cache.S defines caches_clean_inval_pou, dcache_clean_inval_poc,
 * __flush_dcache_area and friends, and exports NONE of them - the file has no
 * EXPORT_SYMBOL at all, and <asm/cacheflush.h> only carries extern prototypes.
 * A module that calls them therefore fails to load.
 *
 * These are three-instruction sequences, so do them here. They operate on
 * virtual addresses and follow the same DC/IC + DSB/ISB ordering the kernel
 * uses in cache.S: maintenance by VA to the point of coherency for the data
 * side, and to the point of unification for the instruction side, then a
 * barrier so the CPU cannot execute stale instructions.
 *
 * CWAY/CWZ are read from CTR_EL0 at runtime rather than assumed: the line
 * sizes are implementation-defined and wrong sizes silently leave stale lines.
 */
static inline unsigned long kp_ctr_dcache_line(void)
{
	unsigned long ctr;

	asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
	return 4UL << ((ctr >> 16) & 0xf);
}

static inline unsigned long kp_ctr_icache_line(void)
{
	unsigned long ctr;

	asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
	return 4UL << (ctr & 0xf);
}

/* Clean and invalidate data cache over [start, end) to the point of
 * coherency, so the kernel's next read sees what we wrote. */
static void kp_flush_dcache(unsigned long start, unsigned long end)
{
	unsigned long line = kp_ctr_dcache_line();
	unsigned long a;

	asm volatile("dsb ishst" ::: "memory");
	for (a = start & ~(line - 1); a < end; a += line)
		asm volatile("dc civac, %0" :: "r"(a) : "memory");
	asm volatile("dsb ish" ::: "memory");
}

/* Invalidate the instruction cache over [start, end) to the point of
 * unification, then synchronise so no stale instruction can execute. */
static void kp_flush_icache(unsigned long start, unsigned long end)
{
	unsigned long line = kp_ctr_icache_line();
	unsigned long a;

	asm volatile("dsb ishst" ::: "memory");
	for (a = start & ~(line - 1); a < end; a += line)
		asm volatile("ic ivau, %0" :: "r"(a) : "memory");
	asm volatile("dsb ish" ::: "memory");
	asm volatile("isb" ::: "memory");
}

/*
 * Walk from the swapper pgd to the leaf entry covering @va.
 *
 * Uses pgd_offset_k(), which needs only a pgd pointer - no mm_struct, so this
 * works without init_mm. Returns the leaf entry (pte_t *), or NULL.
 *
 * Block mappings are returned as-is for PUD and PMD: on arm64 a 2M or 1G block
 * has no PTE below it, and treating it as "no mapping" (the old behaviour) made
 * every large mapping unmodifiable.
 */
static uint64_t *kp_pte_of(uint64_t va)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	if (!kp_swapper_pg_dir)
		return NULL;

	/* pgd_offset_k() expands to &init_mm.pgd[...], and init_mm is not an
	 * exported symbol on this kernel. swapper_pg_dir IS the kernel's top-level
	 * table, so index it directly: the result is identical, without the
	 * dependency on init_mm. */
	pgd = (pgd_t *)&kp_swapper_pg_dir[pgd_index(va)];
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return NULL;
#if defined(p4d_leaf)
	if (p4d_leaf(*p4d))
		return (uint64_t *)p4d;
#endif

	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;
	if (pud_sect(*pud))
		return (uint64_t *)pud;

	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;
	if (pmd_sect(*pmd))
		return (uint64_t *)pmd;

	{
		pte_t *pte = pte_offset_kernel(pmd, va);

		if (!pte || !pte_present(*pte))
			return NULL;
		return (uint64_t *)pte;
	}
}

/* Which level did kp_pte_of() return? Needed to write back through the right
 * accessor, because a block entry is a pud_t/pmd_t, not a pte_t. */
enum kp_leaf_level { KP_LEAF_NONE = 0, KP_LEAF_P4D, KP_LEAF_PUD, KP_LEAF_PMD, KP_LEAF_PTE };

static enum kp_leaf_level kp_leaf_of(uint64_t va, uint64_t **out)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	*out = NULL;
	if (!kp_swapper_pg_dir)
		return KP_LEAF_NONE;

	/* pgd_offset_k() expands to &init_mm.pgd[...], and init_mm is not an
	 * exported symbol on this kernel. swapper_pg_dir IS the kernel's top-level
	 * table, so index it directly: the result is identical, without the
	 * dependency on init_mm. */
	pgd = (pgd_t *)&kp_swapper_pg_dir[pgd_index(va)];
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return KP_LEAF_NONE;
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return KP_LEAF_NONE;
#if defined(p4d_leaf)
	if (p4d_leaf(*p4d)) {
		*out = (uint64_t *)p4d;
		return KP_LEAF_P4D;
	}
#endif
	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
		return KP_LEAF_NONE;
	if (pud_sect(*pud)) {
		*out = (uint64_t *)pud;
		return KP_LEAF_PUD;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return KP_LEAF_NONE;
	if (pmd_sect(*pmd)) {
		*out = (uint64_t *)pmd;
		return KP_LEAF_PMD;
	}
	{
		pte_t *pte = pte_offset_kernel(pmd, va);

		if (!pte || !pte_present(*pte))
			return KP_LEAF_NONE;
		*out = (uint64_t *)pte;
		return KP_LEAF_PTE;
	}
}

/* Rewrite one leaf entry, preserving everything except the bits we own. */
static void kp_write_leaf(enum kp_leaf_level lvl, uint64_t *ent, uint64_t val)
{
	switch (lvl) {
	case KP_LEAF_P4D:
		set_p4d((p4d_t *)ent, __p4d(val));
		break;
	case KP_LEAF_PUD:
		set_pud((pud_t *)ent, __pud(val));
		break;
	case KP_LEAF_PMD:
		set_pmd((pmd_t *)ent, __pmd(val));
		break;
	case KP_LEAF_PTE:
		set_pte((pte_t *)ent, __pte(val));
		break;
	default:
		break;
	}
}

/*
 * Make the pages backing @addr..@addr+size executable at EL1 and disable BTI
 * checking on them.
 *
 * PXN must be 0 (else the first BR faults) and GP must be 0 (else the CPU
 * enforces BTI on a copied trampoline that cannot satisfy it). UXN is forced
 * to 1: these pages are kernel-only, and clearing UXN would let EL0 branch
 * into them.
 *
 * This is exactly what set_memory_x() would do, implemented here because that
 * function is not exported to modules on this kernel.
 */
static int kp_make_executable(void *addr, unsigned long size)
{
	unsigned long start = (unsigned long)addr;
	unsigned long end = start + size;
	unsigned long a;
	int touched = 0;

	if (!addr || !size)
		return -EINVAL;
	if (!is_vmalloc_addr(addr))
		return -EINVAL;

	for (a = start; a < end; a += PAGE_SIZE) {
		uint64_t *ent = NULL;
		enum kp_leaf_level lvl = kp_leaf_of(a, &ent);
		uint64_t v;

		if (lvl == KP_LEAF_NONE || !ent)
			continue;

		v = READ_ONCE(*ent);
		if (!(v & KP_PTE_PXN) && !(v & KP_PTE_GP) && (v & KP_PTE_UXN))
			continue;	/* already in the state we want */

		v &= ~(KP_PTE_PXN | KP_PTE_GP);
		v |= KP_PTE_UXN;
		kp_write_leaf(lvl, ent, v);
		flush_tlb_kernel_range(a, a + PAGE_SIZE);
		touched++;
	}

	if (!touched)
		logkw("make_executable: no entry changed for %px..%px\n", addr, addr + size);

	/* The instruction cache still holds stale lines for the trampoline bytes
	 * the caller is about to copy in; the caller flushes again afterwards. */
	return 0;
}

/* ---- read-only data patch (sys_call_table and friends) ---------------- */

__attribute__((no_sanitize("cfi")))
static unsigned long kp_phys_from_virt(unsigned long addr)
{
	uint64_t *ent = NULL;
	enum kp_leaf_level lvl = kp_leaf_of(addr, &ent);
	uint64_t v;

	if (lvl == KP_LEAF_NONE || !ent)
		return 0;

	v = READ_ONCE(*ent);
	if (!(v & 0x1))		/* PTE_VALID */
		return 0;

	switch (lvl) {
	case KP_LEAF_PTE:
		return (v & 0x0000FFFFFFFFF000UL) | (addr & ~PAGE_MASK);
	case KP_LEAF_PMD:
		return (v & 0x0000FFFFFFE00000UL) | (addr & ~PMD_MASK);
	case KP_LEAF_PUD:
		return (v & 0x0000FFFFC0000000UL) | (addr & ~PUD_MASK);
	default:
		return 0;
	}
}

/* Write @len bytes into kernel memory that may be mapped read-only.
 *
 * This used to go through set_fixmap_offset(FIX_TEXT_POKE0, ...) and
 * copy_to_kernel_nofault(). Neither is usable in a module on this kernel:
 *
 *   __set_fixmap            defined in arch/arm64/mm/fixmap.c, NOT exported
 *   copy_to_kernel_nofault  defined in mm/maccess.c,           NOT exported
 *
 * Both are referenced by the macros above, so even naming them compiles into
 * undefined symbols and the loader refuses the module.
 *
 * The page tables are ours to walk anyway (kp_leaf_of already does it for the
 * executable mapping), so do it here: find the leaf entry covering @dst,
 * temporarily set PTE_DBM and clear PTE_RDONLY, write the bytes, then put the
 * original protection back and flush the TLB. That is the same sequence the
 * kernel's own patch_mapping() uses, and it needs no helpers at all.
 */
__attribute__((no_sanitize("cfi")))
static int kp_patch_data(void *dst, const void *src, size_t len)
{
	unsigned long addr = (unsigned long)dst;
	unsigned long off = addr & ~PAGE_MASK;
	uint64_t *ent = NULL;
	enum kp_leaf_level lvl;
	uint64_t orig;
	uint64_t tmp;

	if (!dst || !len)
		return -EINVAL;

	lvl = kp_leaf_of(addr, &ent);
	if (lvl != KP_LEAF_PTE || !ent) {
		/* Only PTE leaves are patched. A block mapping would need the whole
		 * 2M/1G page to be split first, which this module never has to do:
		 * the targets are vmalloc pages and small .rodata tables. */
		logke("patch_data: no PTE for %px\n", dst);
		return -ENOENT;
	}

	orig = READ_ONCE(*ent);

	/* Writable + dirty at EL1. DBM=1 with RDONLY=0 is the arm64 hardware
	 * dirty-bit way to allow stores; it is what the kernel's set_memory_rw
	 * ends up doing on a PTE. */
	tmp = (orig | KP_PTE_DBM) & ~KP_PTE_RDONLY;
	tmp |= KP_PTE_UXN;		/* keep EL0 out of it */
	set_pte((pte_t *)ent, __pte(tmp));
	flush_tlb_kernel_range(addr & PAGE_MASK, (addr & PAGE_MASK) + PAGE_SIZE);
	dsb(ish);

	memcpy((void *)(addr & PAGE_MASK) + off, src, len);

	/* Put the original protection back and flush again so no stale writable
	 * translation survives on any CPU. */
	set_pte((pte_t *)ent, __pte(orig));
	flush_tlb_kernel_range(addr & PAGE_MASK, (addr & PAGE_MASK) + PAGE_SIZE);
	dsb(ish);

	kp_flush_dcache(addr, addr + len);
	return 0;
}

int kp_patch_memory_init(void)
{
	kp_swapper_pg_dir = (uint64_t *)kp_resolve_symbol("swapper_pg_dir");
	if (!kp_swapper_pg_dir)
		kp_swapper_pg_dir = (uint64_t *)kp_resolve_symbol("init_pg_dir");

	logki("patch memory: swapper_pg_dir=%px\n", (void *)kp_swapper_pg_dir);
	if (!kp_swapper_pg_dir)
		logke("patch memory: no swapper page tables, data patching and "
		      "executable-mapping control disabled\n");
	return 0;
}

int kp_patch_text(void *dst, const void *src, size_t len, int flags)
{
	int ret = kp_patch_data(dst, src, len);

	if (!ret && (flags & KP_PATCH_TEXT_FLUSH_ICACHE))
		kp_flush_icache((unsigned long)dst, (unsigned long)dst + len);
	return ret;
}

/*
 * Allocate @size bytes of executable kernel memory.
 *
 * vmalloc gives PAGE_KERNEL (PXN set); kp_make_executable() then clears PXN/GP
 * on the new pages so the trampoline is enterable by BR. This is the only path
 * available to a module on this kernel - see the file header for the full list
 * of exported helpers that were checked and rejected.
 */
void *kp_alloc_exec(unsigned long size)
{
	void *p;

	if (!size)
		return NULL;

	p = vmalloc(size);
	if (!p) {
		logke("alloc_exec: vmalloc(%lu) failed\n", size);
		return NULL;
	}
	memset(p, 0, size);

	if (kp_make_executable(p, PAGE_ALIGN(size))) {
		vfree(p);
		return NULL;
	}
	return p;
}

void kp_free_exec(void *p)
{
	if (p)
		vfree(p);
}

#endif /* __aarch64__ */
