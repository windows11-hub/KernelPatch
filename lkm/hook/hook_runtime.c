// SPDX-License-Identifier: GPL-2.0-or-later
/* LKM backends required by kernel/base/hook.c. */
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/sched/task_stack.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include "../include/kp_lkm.h"
#include "../include/kp_call.h"
#include <hook.h>
#include "../infra/patch_memory.h"
#include "../infra/symbol_resolver.h"

struct kp_hook_mem {
	struct list_head list;
	uintptr_t origin;
	enum hook_type type;
	void *region;
	union {
		hook_t hook;
		hook_chain_t chain;
		fp_hook_chain_t fp_chain;
	} *payload;
};

static LIST_HEAD(kp_hook_mems);
static DEFINE_MUTEX(kp_hook_lock);
/* Executable-memory allocators. module_alloc exists through 6.10 (__weak in
 * 6.6); 6.11+ replaced it with execmem_alloc() (EXECMEM_MODULE_TEXT).
 * vmalloc is the universal last resort (still needs set_memory_x to be
 * executable on arm64). On 6.11+ the execmem typedef must use the kernel's
 * enum execmem_type so the kCFI type-hash at the indirect call matches. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
#include <linux/execmem.h>
static void *(*kp_hook_execmem_alloc)(enum execmem_type type, size_t size);
static void (*kp_hook_execmem_free)(void *ptr);
#else
static void *(*kp_hook_execmem_alloc)(int type, size_t size);
static void (*kp_hook_execmem_free)(void *ptr);
#endif
static void *(*kp_hook_module_alloc)(unsigned long size);
static void (*kp_hook_module_memfree)(void *region);
/* __vmalloc_node_range: the only exported call that returns executable memory
 * in one step on this kernel. Typed with the 6.6 argument list. */
typedef void *(*kp_vmalloc_range_t)(unsigned long size, unsigned long align,
				    unsigned long start, unsigned long end,
				    gfp_t gfp_mask, pgprot_t prot,
				    unsigned long vm_flags, int node,
				    const void *caller);
static kp_vmalloc_range_t kp_hook_vmalloc_range;
static void (*kp_hook_flush_icache_all)(void);
static int (*kp_hook_set_memory_x)(unsigned long addr, int numpages);

/*
 * Clear PXN / UXN / GP on a range of kernel pages (arm64).
 *
 * This is the part that was missing and the reason every inline hook faulted
 * on GKI 6.6. module_alloc()/vmalloc() hand back PAGE_KERNEL: executable
 * permission still has to be granted (set_memory_x does that), but the GP bit
 * is what gates BTI. With GP set, the CPU requires a valid landing pad
 * (bti c / bti j / bti jc) at every indirect branch target. A copied trampoline
 * page cannot satisfy that for arbitrary entries, and a BR into module text
 * compiled with "bti c" faults outright. Clearing GP tells the CPU not to
 * check BTI for these pages, which is exactly the guarantee a hook trampoline
 * needs: its entries are entered by BR, not by BL.
 *
 * Same bits and same technique as kp_clear_bti_gp() in kpm/module.c: walk the
 * page tables of init_mm, rewrite the PTE, flush the TLB for that page. */
#define KP_HR_PTE_PXN (1UL << 53)
#define KP_HR_PTE_UXN (1UL << 54)
#define KP_HR_PTE_GP  (1UL << 50)

static struct mm_struct *kp_hook_init_mm;

static void kp_hook_clear_exec_bits(unsigned long base, unsigned long size)
{
	unsigned long addr, end;

	if (!kp_hook_init_mm)
		return;
	/* Walking the page tables of a bogus address reads arbitrary memory at
	 * *pgd. Only bracket the vmalloc area; anything else is not ours. */
	if (!base || !is_vmalloc_addr((void *)base))
		return;
	if (size == 0 || size > (1UL << 24))
		return;

	end = base + size;
	for (addr = base; addr < end; addr += PAGE_SIZE) {
		pgd_t *pgd = pgd_offset(kp_hook_init_mm, addr);
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;
		pteval_t v;

		if (pgd_none(*pgd) || pgd_bad(*pgd))
			continue;
		p4d = p4d_offset(pgd, addr);
		if (p4d_none(*p4d) || p4d_bad(*p4d))
			continue;
		pud = pud_offset(p4d, addr);
		if (pud_none(*pud) || pud_bad(*pud))
			continue;
		/* A PUD block mapping IS the leaf: there is no PTE below it. Patching
		 * the block descriptor directly is the correct action, and silently
		 * skipping it (as the previous version did) left 1GB/2MB mapped
		 * trampoline pages with PXN still set - they then faulted on entry. */
		if (pud_sect(*pud)) {
			pteval_t bv = pud_val(*pud);

			if (bv & (KP_HR_PTE_PXN | KP_HR_PTE_GP)) {
				pud_t nv = __pud((bv & ~(KP_HR_PTE_PXN | KP_HR_PTE_GP)) |
						 KP_HR_PTE_UXN);
				set_pud(pud, nv);
				flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
			}
			continue;
		}
		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd) || pmd_bad(*pmd))
			continue;
		if (pmd_sect(*pmd)) {
			pteval_t bv = pmd_val(*pmd);

			if (bv & (KP_HR_PTE_PXN | KP_HR_PTE_GP)) {
				pmd_t nv = __pmd((bv & ~(KP_HR_PTE_PXN | KP_HR_PTE_GP)) |
						 KP_HR_PTE_UXN);
				set_pmd(pmd, nv);
				flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
			}
			continue;
		}
		pte = pte_offset_kernel(pmd, addr);
		if (!pte || !pte_present(*pte))
			continue;

		/*
		 * Clear PXN and GP only.
		 *
		 * PXN=1 means "no execution at EL1", so a trampoline page with it set
		 * faults the moment the BR lands. GP=1 turns BTI back on for the page,
		 * and a copied trampoline cannot satisfy BTI for arbitrary entries -
		 * that is the whole reason this helper exists.
		 *
		 * UXN is NOT cleared. It means "no execution at EL0", and kernel pages
		 * are supposed to keep it set: clearing it would make every trampoline
		 * page a place user mode could branch into, which is a privilege
		 * boundary hole for no functional gain. The trampoline is only ever
		 * entered from EL1.
		 */
		v = pte_val(*pte);
		if (v & (KP_HR_PTE_PXN | KP_HR_PTE_GP)) {
			v &= ~(KP_HR_PTE_PXN | KP_HR_PTE_GP);
			v |= KP_HR_PTE_UXN;
			set_pte(pte, __pte(v));
			flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
		}
	}
}

/* noinline: these are raw resolved function pointers; if inlined into a
 * CFI-instrumented caller, the compiler emits a kCFI type-hash load of
 * [fnptr - 4] that dereferences NULL when the allocator is absent (6.10+ has
 * no module_alloc) and panics. no_sanitize keeps the indirect calls unchecked. */
/* Is @p a plausible kernel allocation we may hand to memset and patch? */
static bool kp_hook_region_ok(void *p, unsigned long size)
{
	unsigned long a = (unsigned long)p;

	if (!p)
		return false;
	if (a + size < a)
		return false;
	if (!is_vmalloc_addr(p))
		return false;
	{
		volatile unsigned long stack_base =
			(unsigned long)task_stack_page(current);
		unsigned long limit = stack_base + THREAD_SIZE;

		if (a >= stack_base && a < limit)
			return false;
		if (a + size > stack_base && a < limit)
			return false;
	}
	return true;
}

/*
 * Allocate executable memory for a hook trampoline.
 *
 * Everything below is built around what the OPPO 6.6 kernel actually exports
 * (checked against oppo-source/android_kernel_oppo_sm8750, sm8750_b_16.0.0):
 *
 *   arch/arm64/mm/pageattr.c exports only set_direct_map_invalid_noflush and
 *   set_direct_map_default_noflush. set_memory_x / set_memory_nx are NOT
 *   exported, so "vmalloc + set_memory_x" cannot work: the call resolves to
 *   NULL, is skipped, and the trampoline ends up in a page with PXN=1. The
 *   first BR into it faults, the Oops escalates to panic, the watchdog resets
 *   the phone. That is exactly the crash loop this module was stuck in.
 *
 *   kernel/module/main.c marks module_alloc and module_memfree __weak and does
 *   not export them either.
 *
 * The one call that does the whole job in a single step is
 * __vmalloc_node_range() with PAGE_KERNEL_EXEC: it allocates inside
 * MODULES_VADDR..MODULES_END and maps the pages executable from the start, so
 * no second pass over the page tables is needed.
 *
 * If that is unavailable, fall back to the old sequence only when both halves
 * exist (an allocator AND set_memory_x), because half of it is worse than
 * failing: a non-executable trampoline is a guaranteed fault later, while a
 * refusal here just disables hooks.
 */
__attribute__((no_sanitize("cfi"), __noinline__))
static void *kp_hook_exec_alloc(unsigned long size)
{
	void *p = NULL;
	unsigned long pages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	/* Preferred: one call, executable from the start. */
	if (kp_hook_vmalloc_range) {
		p = kp_hook_vmalloc_range(size, PAGE_SIZE,
					  VMALLOC_START, VMALLOC_END,
					  GFP_KERNEL | __GFP_ZERO,
					  PAGE_KERNEL_EXEC,
					  VM_FLUSH_RESET_PERMS,
					  NUMA_NO_NODE,
					  __builtin_return_address(0));
		if (p && kp_hook_region_ok(p, size)) {
			logki("exec_alloc: %lu bytes at %px (vmalloc_range, exec)\n", size, p);
			return p;
		}
		if (p) {
			logkw("exec_alloc: vmalloc_range returned %px, rejected\n", p);
			vfree(p);
			p = NULL;
		}
	}

	/* Secondary: a plain allocation plus an explicit permission change, but
	 * ONLY when both pieces resolved. Without set_memory_x the result would be
	 * non-executable and every later BR would fault. */
	if (kp_hook_module_alloc && kp_hook_set_memory_x) {
		void *q = kp_hook_module_alloc(size);

		if (q && kp_hook_region_ok(q, size)) {
			(void)kp_call2((void *)kp_hook_set_memory_x,
				       (unsigned long)q, (unsigned long)pages);
			logki("exec_alloc: %lu bytes at %px (module_alloc + set_memory_x)\n",
			      size, q);
			return q;
		}
	}

	logke("exec_alloc: no executable-memory path for %lu bytes "
	      "(vmalloc_range=%px module_alloc=%px set_memory_x=%px); "
	      "hooks disabled\n",
	      size, (void *)kp_hook_vmalloc_range,
	      (void *)kp_hook_module_alloc, (void *)kp_hook_set_memory_x);
	return NULL;
}

__attribute__((no_sanitize("cfi"), __noinline__))
static void kp_hook_exec_free(void *region)
{
	if (kp_hook_module_memfree)
		(void)kp_call1((void *)kp_hook_module_memfree, (unsigned long)region);
	else if (kp_hook_execmem_free)
		(void)kp_call1((void *)kp_hook_execmem_free, (unsigned long)region);
	else
		vfree(region);
}

__attribute__((no_sanitize("cfi")))
static void kp_hook_flush_all(void)
{
	if (kp_hook_flush_icache_all)
		(void)kp_call0((void *)kp_hook_flush_icache_all);
}

int kp_hook_runtime_init(void)
{
	/* One symbol per line, logged BEFORE and AFTER each lookup.
	 *
	 * This used to be seven lookups and one summary line, so a crash anywhere
	 * in here produced no evidence at all - the watchdog reset destroyed the
	 * buffer before anyone could read it. Now the last line in dmesg names the
	 * exact symbol being resolved when the module dies.
	 *
	 * kallsyms_lookup_name() walks the compressed kallsyms tables and can fault
	 * on a malformed/mismatched table, which is one of the things this staging
	 * is meant to distinguish from a bad pointer later. */
#define KP_RESOLVE(dst, name)                                            \
	do {                                                             \
		logki("sym: resolving %s\n", name);                      \
		(dst) = (void *)kp_resolve_symbol(name);                 \
		logki("sym: %s = %px\n", name, (void *)(dst));            \
	} while (0)

	logki("hook runtime: begin\n");

	KP_RESOLVE(kp_hook_module_alloc, "module_alloc");
	KP_RESOLVE(kp_hook_module_memfree, "module_memfree");
	KP_RESOLVE(kp_hook_execmem_alloc, "execmem_alloc");
	KP_RESOLVE(kp_hook_execmem_free, "execmem_free");
	KP_RESOLVE(kp_hook_flush_icache_all, "flush_icache_all");
	KP_RESOLVE(kp_hook_set_memory_x, "set_memory_x");
	KP_RESOLVE(kp_hook_init_mm, "init_mm");

#undef KP_RESOLVE

	if (!kp_hook_init_mm)
		logkw("init_mm not found; hook pages keep the GP bit set and BTI will fault\n");
	if (!kp_hook_module_alloc)
		logkw("module_alloc not found; using execmem_alloc/vmalloc for hook memory\n");
	if (!kp_hook_set_memory_x && !kp_hook_execmem_alloc) {
		logke("no executable-memory path (set_memory_x/execmem_alloc missing)\n");
		return -ENOSYS;
	}

	logki("hook runtime: probing allocator\n");
	{
		/* Allocate and free one page here, at init time, on purpose: if the
		 * resolved allocator is not what its name claims, this is where it
		 * shows up - inside a function whose only job is to fail cleanly -
		 * instead of later inside a hook that cannot recover. */
		void *probe = kp_hook_exec_alloc(PAGE_SIZE);

		if (!probe) {
			logke("hook runtime: allocator probe failed, hooks disabled\n");
			return -ENOMEM;
		}
		logki("hook runtime: allocator probe ok at %px\n", probe);
		kp_hook_exec_free(probe);
		logki("hook runtime: allocator probe freed\n");
	}

	logki("KPM hook runtime ready (module_alloc=%px execmem_alloc=%px set_memory_x=%px)\n",
	      kp_hook_module_alloc, kp_hook_execmem_alloc, kp_hook_set_memory_x);
	return 0;
}

void *hook_mem_zalloc(uintptr_t origin, enum hook_type type)
{
	struct kp_hook_mem *mem;
	size_t size;

	switch (type) {
	case INLINE:
		size = sizeof(hook_t);
		break;
	case INLINE_CHAIN:
		size = sizeof(hook_chain_t);
		break;
	case FUNCTION_POINTER_CHAIN:
		size = sizeof(fp_hook_chain_t);
		break;
	default:
		return NULL;
	}

	mem = kzalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem)
		return NULL;
	mem->region = kp_hook_exec_alloc(PAGE_ALIGN(size));
	if (!mem->region) {
		kfree(mem);
		return NULL;
	}
	memset(mem->region, 0, PAGE_ALIGN(size));
	mem->payload = mem->region;
	mem->origin = origin;
	mem->type = type;
	mutex_lock(&kp_hook_lock);
	list_add_tail(&mem->list, &kp_hook_mems);
	mutex_unlock(&kp_hook_lock);
	return mem->payload;
}

void *hook_get_mem_from_origin(uint64_t origin)
{
	struct kp_hook_mem *mem;
	void *result = NULL;

	mutex_lock(&kp_hook_lock);
	list_for_each_entry(mem, &kp_hook_mems, list) {
		if (mem->origin == origin) {
			result = mem->payload;
			break;
		}
	}
	mutex_unlock(&kp_hook_lock);
	return result;
}

void hook_mem_free(void *payload)
{
	struct kp_hook_mem *mem, *tmp;

	mutex_lock(&kp_hook_lock);
	list_for_each_entry_safe(mem, tmp, &kp_hook_mems, list) {
		if (mem->payload == payload) {
			list_del(&mem->list);
			mutex_unlock(&kp_hook_lock);
			kp_hook_exec_free(mem->region);
			kfree(mem);
			return;
		}
	}
	mutex_unlock(&kp_hook_lock);
}

int hotpatch(void *addrs[], uint32_t values[], int count)
{
	int i, start, rc;

	for (start = 0; start < count; start = i) {
		for (i = start + 1; i < count; i++) {
			if ((char *)addrs[i] != (char *)addrs[start] +
						 (i - start) * sizeof(values[0]))
				break;
		}
		rc = kp_patch_text(addrs[start], &values[start],
				   (i - start) * sizeof(values[0]),
				   KP_PATCH_TEXT_FLUSH_DCACHE | KP_PATCH_TEXT_FLUSH_ICACHE);
		if (rc)
			return rc;
	}
	return 0;
}

void flush_icache_all(void)
{
	kp_hook_flush_all();
}
