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
		if (pud_sect(*pud))
			continue;
		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd) || pmd_bad(*pmd))
			continue;
		if (pmd_sect(*pmd))
			continue;
		pte = pte_offset_kernel(pmd, addr);
		if (!pte || !pte_present(*pte))
			continue;

		v = pte_val(*pte);
		if (v & (KP_HR_PTE_PXN | KP_HR_PTE_UXN | KP_HR_PTE_GP)) {
			v &= ~(KP_HR_PTE_PXN | KP_HR_PTE_UXN | KP_HR_PTE_GP);
			set_pte(pte, __pte(v));
			flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
		}
	}
}

/* noinline: these are raw resolved function pointers; if inlined into a
 * CFI-instrumented caller, the compiler emits a kCFI type-hash load of
 * [fnptr - 4] that dereferences NULL when the allocator is absent (6.10+ has
 * no module_alloc) and panics. no_sanitize keeps the indirect calls unchecked. */
/* Is @p a plausible kernel allocation we may hand to memset and patch?
 *
 * This check exists because of a real crash: kp_resolve_symbol("module_alloc")
 * resolved to something that was not module_alloc on a 6.6 GKI kernel, the call
 * returned a stack address, and kp_hook_mem_zalloc() memset it - the DC ZVA in
 * __memset ran off the 16K VMAP_STACK into the guard page and the Oops escalated
 * to panic (panic_on_oops=1) and then to a hypervisor watchdog reset.
 *
 * Rejecting the value here turns "kernel dies with no usable trace" into "hook
 * not installed, one warning in dmesg". */
static bool kp_hook_region_ok(void *p, unsigned long size)
{
	unsigned long a = (unsigned long)p;

	if (!p)
		return false;
	if (a + size < a)		/* overflow */
		return false;

	/* Reject anything that is not in the vmalloc/module area. This is the
	 * cheap first filter, NOT a sufficient one - see the stack check below. */
	if (!is_vmalloc_addr(p))
		return false;

	/*
	 * VMAP_STACK puts kernel thread stacks INSIDE the vmalloc area, so
	 * is_vmalloc_addr() happily accepts a stack address. That is exactly how
	 * this module died: kp_hook_exec_alloc() returned a stack pointer
	 * (ffffffc0adfd3788, just below sp), the caller memset 4K over it, the
	 * DC ZVA in __memset ran into the 16K stack guard page (PTE = 0), and the
	 * resulting Oops escalated to panic and then to a watchdog reset.
	 *
	 * object_is_on_stack() would be the natural check, but it is a static
	 * inline over task_stack_page(current) and the compiler proves it false
	 * for a value returned by an indirect call - the whole test is eliminated
	 * (verified in the built object: no reference to it survives). Compare
	 * against the current stack range through a volatile pointer instead, so
	 * the compiler must keep the comparison.
	 */
	{
		volatile unsigned long stack_base =
			(unsigned long)task_stack_page(current);
		unsigned long limit = stack_base + THREAD_SIZE;
		unsigned long a2 = a;

		if (a2 >= stack_base && a2 < limit)
			return false;
		/* Also reject the guard gap just below and above the stack: a 4K
		 * memset starting near the top would still cross into the guard
		 * page, which has no PTE. */
		if (a2 + size > stack_base && a2 < limit)
			return false;
	}

	/* Also reject the module image itself and any other kernel text/data the
	 * allocator should never have returned. A module_alloc result is always
	 * in the vmalloc area and never inside the running module's own ranges. */
	if (a >= (unsigned long)&_stext && a < (unsigned long)&_end)
		return false;

	return true;
}

__attribute__((no_sanitize("cfi"), __noinline__))
static void *kp_hook_exec_alloc(unsigned long size)
{
	void *p = NULL;
	unsigned long pages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	/* Direct calls. The function is already no_sanitize("cfi") and the
	 * pointers carry their real prototypes, so kp_callN() buys nothing here
	 * and only obscures the return value. */
	if (kp_hook_module_alloc) {
		p = kp_hook_module_alloc(size);
		if (!kp_hook_region_ok(p, size)) {
			logkw("exec_alloc: module_alloc(%lu) returned %px, not a vmalloc region\n",
			      size, p);
			p = NULL;
		}
	}
	if (!p && kp_hook_execmem_alloc) {
		p = kp_hook_execmem_alloc(0 /* EXECMEM_MODULE_TEXT */, size);
		if (!kp_hook_region_ok(p, size)) {
			logkw("exec_alloc: execmem_alloc(%lu) returned %px, not a vmalloc region\n",
			      size, p);
			p = NULL;
		}
	}
	if (!p) {
		p = vmalloc(size);
		if (!kp_hook_region_ok(p, size)) {
			logkw("exec_alloc: vmalloc(%lu) returned %px\n", size, p);
			p = NULL;
		}
	}
	if (!p) {
		logke("exec_alloc: no usable executable memory for %lu bytes\n", size);
		return NULL;
	}
	/* GKI module_alloc returns PAGE_KERNEL (PXN set, NX); vmalloc too. Hook
	 * trampolines live here and must be executable. */
	if (kp_hook_set_memory_x)
		(void)kp_call2((void *)kp_hook_set_memory_x, (unsigned long)p, (unsigned long)pages);
	/*
	 * set_memory_x only grants execution. The GP bit is still set, so the
	 * CPU keeps enforcing BTI on these pages and any BR into the trampoline
	 * faults. Clear PXN/UXN/GP so the trampoline is enterable by BR, which
	 * is how hook_chain_prepare() transfers control (LDR X16 + BR X16).
	 */
	kp_hook_clear_exec_bits((unsigned long)p, pages << PAGE_SHIFT);
	return p;
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
