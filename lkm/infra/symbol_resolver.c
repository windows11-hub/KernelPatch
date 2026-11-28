// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Runtime symbol resolver for the LKM.
 *
 * Facts established from the 6.6 source, which this file is built around:
 *
 *   kernel/kallsyms.c in v6.6 exports exactly three symbols, all _GPL:
 *   sprint_symbol, sprint_symbol_build_id, sprint_symbol_no_offset.
 *   kallsyms_lookup_name and kallsyms_on_each_symbol are NOT exported
 *   anywhere in mainline 6.6.
 *
 *   arch/arm64/mm/pageattr.c exports nothing at all, so set_memory_nx / _x
 *   are not reachable by name either.
 *
 *   kernel/module/main.c marks module_alloc and module_memfree __weak and
 *   does not export them.
 *
 * A module that names any of those would be rejected by the loader with
 * "Unknown symbol". This module loads, so the device's vendor kernel exports
 * some of them - which ones is exactly what the log line in kp_symres_init()
 * reports.
 *
 * Therefore: reach kallsyms_lookup_name by its linked symbol only (the kernel
 * build guarantees it resolves or the module would not load at all), and treat
 * kallsyms_on_each_symbol as optional. Referencing the latter through the
 * assembler keeps the object free of a hard dependency on it: if the vendor
 * kernel does not export it, adrp still produces a number and kp_each_addr
 * simply fails the "is it inside the kernel image" check below.
 */
#include "symbol_resolver.h"

#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>

#include "../include/kp_lkm.h"

extern uint32_t kver;
#ifndef VERSION
#define VERSION(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))
#endif

#define KP_SYM_CACHE_MAX 32

struct kp_sym_entry {
	const char *name;
	unsigned long addr;
};

static struct kp_sym_entry kp_sym_cache[KP_SYM_CACHE_MAX];
static int kp_sym_cache_count;
static bool kp_sym_cache_ready;

/* kallsyms_on_each_symbol, taken without a prototype. */
static unsigned long kp_each_addr;

/* ---- table walk ------------------------------------------------------- */

struct kp_walk_ctx {
	const char *want;
	unsigned long addr;
};

static int kp_walk_match(void *data, const char *name, unsigned long addr)
{
	struct kp_walk_ctx *ctx = data;

	if (!name || !addr)
		return 0;
	if (!strcmp(name, ctx->want)) {
		ctx->addr = addr;
		return 1;
	}
	return 0;
}

typedef int (*kp_walk_cb3_t)(void *, const char *, unsigned long);
typedef int (*kp_walk_cb4_t)(void *, const char *, struct module *, unsigned long);
typedef int (*kp_each_3_t)(kp_walk_cb3_t, void *);
typedef int (*kp_each_4_t)(kp_walk_cb4_t, void *, struct module *);

static int kp_walk_cb3(void *data, const char *name, unsigned long addr)
{
	return kp_walk_match(data, name, addr);
}

static int kp_walk_cb4(void *data, const char *name, struct module *m, unsigned long addr)
{
	(void)m;
	return kp_walk_match(data, name, addr);
}

static unsigned long kp_walk_lookup(const char *name)
{
	struct kp_walk_ctx ctx = { .want = name, .addr = 0 };

	if (!kp_each_addr)
		return 0;

	/* The call shape follows the RUNNING kernel. Vendor 5.10/5.15 trees may
	 * carry the three-argument backport, 6.4+ always has four. Passing the
	 * wrong count leaves x2 holding whatever the compiler left there, which
	 * the kernel then dereferences as struct module *. */
	if (kver >= VERSION(6, 4, 0))
		(void)((kp_each_4_t)kp_each_addr)(kp_walk_cb4, &ctx, NULL);
	else
		(void)((kp_each_3_t)kp_each_addr)(kp_walk_cb3, &ctx);

	return ctx.addr;
}

/* ---- public API ------------------------------------------------------- */

unsigned long kp_resolve_symbol(const char *name)
{
	unsigned long addr;
	int i;

	if (!name)
		return 0;

	if (kp_sym_cache_ready) {
		for (i = 0; i < kp_sym_cache_count; i++) {
			if (!strcmp(kp_sym_cache[i].name, name))
				return kp_sym_cache[i].addr;
		}
	}

	/* kallsyms_lookup_name is linked (its declaration is in
	 * <linux/kallsyms.h> and the module would not load if the kernel did not
	 * provide it), so call it directly. This is the reliable path. */
	addr = kallsyms_lookup_name(name);

	/* Walk the table only if the direct lookup came up empty and the walk is
	 * available. Never call the walk first: on a kernel that does not export
	 * kallsyms_on_each_symbol the pointer is garbage and calling it faults. */
	if (!addr)
		addr = kp_walk_lookup(name);

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
	unsigned long lookup;

	kp_sym_cache_count = 0;
	kp_sym_cache_ready = true;

	/* Report the one address that decides whether any of this can work. */
	lookup = (unsigned long)kallsyms_lookup_name;
	logki("symbol resolver: kallsyms_lookup_name=%px\n", (void *)lookup);
	if (!lookup)
		logke("symbol resolver: kallsyms_lookup_name is NULL, no symbol can be resolved\n");

	/* Optional. adrp/add yields a plain integer, so referencing a symbol the
	 * kernel may not export does not create a link dependency. */
	kp_each_addr = 0;
	asm volatile("adrp %0, kallsyms_on_each_symbol\n\t"
		     "add  %0, %0, :lo12:kallsyms_on_each_symbol"
		     : "=r"(kp_each_addr));

	/* If the symbol does not exist the linker still placed something there;
	 * reject anything that is not a plausible kernel text address. */
	if (kp_each_addr < 0xffffff8000000000UL) {
		logki("symbol resolver: kallsyms_on_each_symbol not usable (%px), walk disabled\n",
		      (void *)kp_each_addr);
		kp_each_addr = 0;
	} else {
		logki("symbol resolver: kallsyms_on_each_symbol=%px\n", (void *)kp_each_addr);
	}

	logki("symbol resolver: ready (kver=%x)\n", kver);
}
