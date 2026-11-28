// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Runtime symbol resolver for the LKM.
 *
 * Everything here follows from one fact, checked against the OPPO 6.6 source
 * (oppo-source/android_kernel_oppo_sm8750, sm8750_b_16.0.0_find_n5):
 *
 *   kernel/kallsyms.c exports exactly three symbols, all _GPL:
 *     sprint_symbol, sprint_symbol_build_id, sprint_symbol_no_offset
 *   kallsyms_lookup_name is NOT in that list for mainline, but the vendor
 *   kernel this module runs on does provide it - the module links against it
 *   and loads, which is proof it is resolvable.
 *
 *   kallsyms_on_each_symbol is NOT exported by that kernel at all. Referencing
 *   it by name - which the previous revision did through an adrp/add pair -
 *   leaves an undefined symbol in the object, and the loader rejects the whole
 *   module with "Unknown symbol kallsyms_on_each_symbol". Taking an address
 *   through the assembler does NOT avoid that: the relocation is still emitted.
 *
 * So this file uses kallsyms_lookup_name and nothing else. There is no table
 * walk, no fallback, no second path that can reintroduce the dependency.
 */
#include "symbol_resolver.h"

#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/version.h>

#include "../include/kp_lkm.h"

#define KP_SYM_CACHE_MAX 64

struct kp_sym_entry {
	const char *name;
	unsigned long addr;
};

static struct kp_sym_entry kp_sym_cache[KP_SYM_CACHE_MAX];
static int kp_sym_cache_count;
static bool kp_sym_cache_ready;

unsigned long kp_resolve_symbol(const char *name)
{
	unsigned long addr;
	int i;

	if (!name)
		return 0;

	/* The cache matters: hook init and selinux_hook both ask for the same
	 * names repeatedly, and each miss walks the compressed kallsyms table. */
	if (kp_sym_cache_ready) {
		for (i = 0; i < kp_sym_cache_count; i++) {
			if (!strcmp(kp_sym_cache[i].name, name))
				return kp_sym_cache[i].addr;
		}
	}

	addr = kallsyms_lookup_name(name);

	if (kp_sym_cache_ready && kp_sym_cache_count < KP_SYM_CACHE_MAX) {
		kp_sym_cache[kp_sym_cache_count].name = name;
		kp_sym_cache[kp_sym_cache_count].addr = addr;
		kp_sym_cache_count++;
	}

	return addr;
}

void *kp_resolve_symbol_variant(const char *name)
{
	char cfi_name[KSYM_NAME_LEN];
	unsigned long jt;
	int n;

	if (!name)
		return NULL;

	/* Traditional CFI (< 6.1) requires calling functions through their .cfi_jt
	 * canonical-jump-table entry rather than the function body: an indirect
	 * call to the body trips __cfi_check. Try the jump table first, fall back
	 * to the plain name. */
	n = snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", name);
	if (n > 0 && n < (int)sizeof(cfi_name)) {
		jt = kp_resolve_symbol(cfi_name);
		if (jt)
			return (void *)jt;
	}

	return (void *)kp_resolve_symbol(name);
}

void kp_symres_init(void)
{
	unsigned long lookup = (unsigned long)kallsyms_lookup_name;

	kp_sym_cache_count = 0;
	kp_sym_cache_ready = true;

	logki("symbol resolver: kallsyms_lookup_name=%px\n", (void *)lookup);
	if (!lookup)
		logke("symbol resolver: kallsyms_lookup_name is NULL; "
		      "no symbol can be resolved and every feature will disable itself\n");
}
