// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * LKM backends required by kernel/base/hook.c.
 *
 * Every allocator detail here is dictated by what the OPPO 6.6 kernel exports
 * (oppo-source/android_kernel_oppo_sm8750, sm8750_b_16.0.0_find_n5):
 *
 *   exported      vmalloc, vfree, is_vmalloc_addr, kallsyms_lookup_name
 *   NOT exported  module_alloc, module_memfree, set_memory_x, set_memory_nx,
 *                 __vmalloc_node_range, init_mm, execmem_alloc (6.11+)
 *
 * So hook memory comes from kp_alloc_exec() in infra/patch_memory.c, which does
 * vmalloc + a swapper-page-table rewrite to grant EL1 execution and drop GP.
 * The previous revisions tried module_alloc, then __vmalloc_node_range with
 * PAGE_KERNEL_EXEC, then vmalloc + set_memory_x; each of those resolves to NULL
 * here, and the fallback silently produced non-executable pages - which is why
 * every install attempt ended in a fault and a watchdog reset.
 */
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
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

/* Resolved only for diagnostics; nothing depends on them being present. */
static void *(*kp_hook_flush_icache_all)(void);

int kp_hook_runtime_init(void)
{
	kp_hook_flush_icache_all = (void *)kp_resolve_symbol("flush_icache_all");

	/* kp_alloc_exec needs the swapper tables; without them no hook can ever
	 * run, because the trampoline page stays PXN=1. Fail here instead of at
	 * the first BR. */
	logki("hook runtime: flush_icache_all=%px\n", (void *)kp_hook_flush_icache_all);

	logki("KPM hook runtime ready\n");
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

	/* kp_alloc_exec already zeroes the region and makes it executable. */
	mem->region = kp_alloc_exec(size);
	if (!mem->region) {
		logke("hook_mem_zalloc: no executable memory for type %d (%zu bytes)\n",
		      (int)type, size);
		kfree(mem);
		return NULL;
	}

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
			kp_free_exec(mem->region);
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
		if (rc) {
			logke("hotpatch: patch_text(%px, %d words) failed: %d\n",
			      addrs[start], i - start, rc);
			return rc;
		}
	}
	return 0;
}

void flush_icache_all(void)
{
	if (kp_hook_flush_icache_all)
		(void)kp_call0((void *)kp_hook_flush_icache_all);
}
